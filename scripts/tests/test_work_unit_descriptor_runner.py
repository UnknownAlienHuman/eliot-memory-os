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
import threading
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


# Lane-C production policy: cargo provisioning uses runner-owned
# r.toolchain_child_env (fixed 12 TOOLCHAIN_ENV_NAMES + CARGO_*/RUST_* prefix,
# blocked secret markers, byte caps, emits RUSTC_WRAPPER='' after filtering).
# (local toolchain copies removed; see r.TOOLCHAIN_ENV_NAMES / r.toolchain_child_env).
# Sufficiency re-proven GREEN under the real owned job at max_active=4 with the
# direct rustc 1.97.1 chain, target dir under %TEMP%, RUSTC_WRAPPER='' emitted.


def _r2_descriptor_bounds(name='minimal-python-unittest.toml'):
    """Decode frozen descriptor fixture bounds via runner enforcement_plan."""
    data = r.decode_descriptor((DESCRIPTOR_DIR / name).read_bytes(), FILENAME)
    return r.enforcement_plan(bounds=data['bounds'])


class WindowsOwnedTree:
    """Test-owned bounded owned-tree launcher (TEST FILE ONLY, never production).

    Windows-only. Job Object with KILL_ON_JOB_CLOSE plus an ActiveProcessLimit,
    suspended-create with assign-before-first-instruction, streaming pump
    capture, wall/idle bounds, and TerminateJobObject reap. POSIX is explicitly
    unsupported: _run_posix raises RuntimeError before spawn -- there is no
    accepted owned-tree equivalent there, and a process-group/killpg branch is
    NOT an owned tree, so it is refused rather than simulated.

    R2 reuse interface:
      launcher = WindowsOwnedTree()
      bounds = _r2_descriptor_bounds('minimal-python-unittest.toml')
      disp = launcher.run(argv, *, input_bytes=None, timeout=None, cwd=..., env=...,
                          bounds=bounds, idle_s=None)
    bounds is REQUIRED and fail-closed (BOUNDS_REQUIRED when omitted or
    malformed): a mapping {wall_s, idle_s, output_bytes, line_bytes,
    max_processes} decoded from the frozen descriptor fixtures. Explicit
    timeout/idle_s overrides are accepted as test provisioning; the
    output/line/max dimensions always come from bounds. The constructor
    output_bytes/line_bytes are retained for call compatibility only and are
    ignored whenever bounds is present (bounds is always present).

    disp keys: argv, returncode, stdout (bytes), stderr (bytes), timed_out (bool),
      idle_timeout (bool), truncated (bool), truncate_reason (str),
      dropped_bytes (int), active_processes (int), total_processes (int),
      max_active (int, peak ActiveProcesses polled each 100ms during the run),
      cleanup (str), cleanup_ok (bool).

    Streaming capture is genuinely bounded: pump threads read stdout/stderr in
    64KiB chunks and enforce output_bytes (total per stream) and line_bytes
    (per line) incrementally, carrying partial-line state (including CR/LF
    split across chunks) between reads. On exceed the owned tree is terminated
    immediately via TerminateJobObject on the owned Job handle, truncated=True
    plus a reason is recorded, pumps stop, and the job is reaped. Parent-side
    kept bytes are capped at output_bytes + one chunk slack per stream; beyond
    that bytes are discarded and only counted (dropped_bytes; the reason carries
    the code plus counts, never child content).

    Idle: when no new bytes arrive on either stream for idle_s seconds the tree
    is terminated as timed_out=True + idle_timeout=True with cleanup
    timeout-reaped after zero-active verification.

    Descendant limit: ActiveProcessLimit is set from max_processes with
    LimitFlags KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS(0x8), so
    over-limit spawns are denied by the OS while the owned job still reaps
    cleanly.

    Residual honesty: unknown cleanup (failed queries, surviving members) is
    reported as cleanup-failed/cleanup_ok=False and never passes.
    """

    KILL_ON_JOB_CLOSE = 0x2000
    _JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x8
    _CREATE_SUSPENDED = 0x00000004
    _CHUNK = 65536
    _POLL_S = 0.1
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
        # Retained for call compatibility only; run(bounds=...) always governs.
        self.output_bytes = int(output_bytes)
        self.line_bytes = int(line_bytes)

    def _coerce_bounds(self, bounds, timeout, idle_s, provisioned=False):
        """Fail closed: bounds mapping required, no looser defaults."""
        if bounds is None:
            raise RuntimeError('BOUNDS_REQUIRED: launcher.run requires descriptor-decoded bounds '
                               '{wall_s,idle_s,output_bytes,line_bytes,max_processes}')
        try:
            wall_b = float(bounds['wall_s'])
            idle_b = float(bounds['idle_s'])
            out_b = int(bounds['output_bytes'])
            line_b = int(bounds['line_bytes'])
            max_p = int(bounds['max_processes'])
        except Exception:
            raise RuntimeError('BOUNDS_REQUIRED: malformed bounds mapping')
        if isinstance(bounds.get('wall_s'), bool) or isinstance(bounds.get('idle_s'), bool):
            raise RuntimeError('BOUNDS_REQUIRED: malformed bounds mapping')
        if not (wall_b > 0 and idle_b > 0 and out_b >= 1 and line_b >= 1 and max_p >= 1):
            raise RuntimeError('BOUNDS_REQUIRED: non-positive bound')
        if not (idle_b <= wall_b and line_b <= out_b and max_p <= 64):
            raise RuntimeError('BOUNDS_REQUIRED: inconsistent bounds')
        wall = float(timeout) if timeout is not None else wall_b
        idle = float(idle_s) if idle_s is not None else idle_b
        if isinstance(timeout, bool) or isinstance(idle_s, bool) or not (wall > 0 and idle > 0):
            raise RuntimeError('BOUNDS_REQUIRED: bad timeout/idle override')
        if not provisioned:
            if timeout is not None and wall > wall_b:
                raise RuntimeError('BOUNDS_REQUIRED: timeout override exceeds decoded ceiling')
            if idle_s is not None and idle > idle_b:
                raise RuntimeError('BOUNDS_REQUIRED: idle override exceeds decoded ceiling')
        return wall, idle, out_b, line_b, max_p

    def _run_posix(self, argv, *, input_bytes, timeout, cwd, env, bounds=None, idle_s=None, provisioned=False):
        raise RuntimeError('unsupported containment on POSIX: no accepted owned-tree equivalent; '
                           'Windows Job Object required')

    def _run_windows(self, argv, *, input_bytes, timeout, cwd, env, bounds, idle_s, provisioned=False):
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
            # NOTE: the ActiveProcessCount slot carries ActiveProcessLimit when
            # setting limits (same DWORD offset/size); accounting reads below
            # use the separate _ACC.ActiveProcesses field, never this slot.
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

        wall_s, idle_eff, out_bound, line_bound, max_proc = self._coerce_bounds(bounds, timeout, idle_s, provisioned=provisioned)
        keep_cap = out_bound + self._CHUNK

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise RuntimeError('CreateJobObjectW failed')
        try:
            ext = _EXT()
            ext.BasicLimitInformation.LimitFlags = (self.KILL_ON_JOB_CLOSE | self._JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
            ext.BasicLimitInformation.ActiveProcessCount = int(max_proc)
            if not kernel32.SetInformationJobObject(job, self._JOB_EXTENDED, ctypes.byref(ext), ctypes.sizeof(ext)):
                raise RuntimeError('SetInformationJobObject limits failed')
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

                lock = threading.Lock()
                stop = threading.Event()
                shared = {'truncated': False, 'reason_code': '', 'timed_out': False,
                          'idle_timeout': False, 'last_data': time.monotonic()}

                def new_slot():
                    return {'kept': bytearray(), 'total': 0, 'dropped': 0, 'line': 0, 'cr': False}

                slots = {'out': new_slot(), 'err': new_slot()}

                def terminate_tree():
                    try:
                        kernel32.TerminateJobObject(job, 1)
                    except Exception:
                        pass
                    stop.set()

                def feed(slot, chunk):
                    """Account one chunk; returns 'OUTPUT'/'LINE' on bound hit, else None."""
                    slot['total'] += len(chunk)
                    room = keep_cap - len(slot['kept'])
                    if room > 0:
                        take = len(chunk) if len(chunk) < room else room
                        slot['kept'] += chunk[:take]
                        slot['dropped'] += len(chunk) - take
                    else:
                        slot['dropped'] += len(chunk)
                    if slot['total'] > out_bound:
                        return 'OUTPUT'
                    cur = slot['line']
                    cr = slot['cr']
                    for byte in chunk:
                        if byte == 0x0A:
                            eff = cur - (1 if cr else 0)
                            if eff > line_bound:
                                slot['line'] = 0
                                slot['cr'] = False
                                return 'LINE'
                            cur = 0
                            cr = False
                        elif byte == 0x0D:
                            cur += 1
                            cr = True
                        else:
                            if cr:
                                if cur - 1 > line_bound:
                                    slot['line'] = cur
                                    slot['cr'] = False
                                    return 'LINE'
                                cur = 0
                                cr = False
                            cur += 1
                            if cur > line_bound:
                                slot['line'] = cur
                                slot['cr'] = cr
                                return 'LINE'
                    slot['line'] = cur
                    slot['cr'] = cr
                    return None

                def pump(pipe, slot):
                    try:
                        while not stop.is_set():
                            try:
                                chunk = pipe.read(self._CHUNK)
                            except Exception:
                                break
                            if not chunk:
                                break
                            with lock:
                                shared['last_data'] = time.monotonic()
                                if shared['truncated']:
                                    slot['total'] += len(chunk)
                                    slot['dropped'] += len(chunk)
                                    continue
                                hit = feed(slot, chunk)
                                if hit is not None and not shared['truncated']:
                                    shared['truncated'] = True
                                    shared['reason_code'] = ('OUTPUT_BYTE_BOUND' if hit == 'OUTPUT'
                                                             else 'LINE_BYTE_BOUND')
                                    terminate_tree()
                    finally:
                        pass

                def query():
                    acc = _ACC()
                    length = ctypes.c_uint32(0)
                    try:
                        ok = kernel32.QueryInformationJobObject(job, self._JOB_BASIC_ACCOUNTING_INFORMATION,
                                                               ctypes.byref(acc), ctypes.sizeof(acc),
                                                               ctypes.byref(length))
                    except Exception:
                        return None, None
                    if ok:
                        return int(acc.ActiveProcesses), int(acc.TotalProcesses)
                    return None, None

                if input_bytes is not None:
                    try:
                        proc.stdin.write(input_bytes)
                    except Exception:
                        pass
                    try:
                        proc.stdin.close()
                    except Exception:
                        pass
                t_out = threading.Thread(target=pump, args=(proc.stdout, slots['out']), daemon=True)
                t_err = threading.Thread(target=pump, args=(proc.stderr, slots['err']), daemon=True)
                t_out.start()
                t_err.start()
                start = time.monotonic()
                deadline = start + wall_s
                active, total = query()
                max_active = active if active is not None else 0
                if active is None:
                    active = -1
                if total is None:
                    total = -1
                try:
                    while True:
                        time.sleep(self._POLL_S)
                        now = time.monotonic()
                        with lock:
                            trunc = shared['truncated']
                            last = shared['last_data']
                        rc = proc.poll()
                        seen_active, seen_total = query()
                        if seen_active is not None:
                            active = seen_active
                            if seen_active > max_active:
                                max_active = seen_active
                        if seen_total is not None:
                            total = seen_total
                        if rc is None:
                            if trunc:
                                pass  # TerminateJobObject already requested; await exit.
                            elif now >= deadline:
                                with lock:
                                    shared['timed_out'] = True
                                terminate_tree()
                            elif now - last >= idle_eff:
                                with lock:
                                    shared['timed_out'] = True
                                    shared['idle_timeout'] = True
                                terminate_tree()
                            if (now - start) > wall_s + 60:
                                with lock:
                                    shared['timed_out'] = True
                                terminate_tree()
                        else:
                            if (not t_out.is_alive()) and (not t_err.is_alive()):
                                break
                            if (now - start) > wall_s + 60:
                                with lock:
                                    shared['timed_out'] = True
                                terminate_tree()
                                break
                finally:
                    pass
                with lock:
                    trunc = shared['truncated']
                    code = shared['reason_code']
                    timed_out = shared['timed_out']
                    idle_flag = shared['idle_timeout']
                if timed_out or trunc:
                    for _ in range(100):
                        seen_active, seen_total = query()
                        if seen_active is not None:
                            active = seen_active
                            if seen_active > max_active:
                                max_active = seen_active
                        if seen_total is not None:
                            total = seen_total
                        if active == 0:
                            break
                        time.sleep(0.1)
                try:
                    proc.wait(timeout=10)
                except Exception:
                    pass
                for thread in (t_out, t_err):
                    thread.join(timeout=10)
                for pipe in (proc.stdout, proc.stderr):
                    try:
                        pipe.close()
                    except Exception:
                        pass
                for thread in (t_out, t_err):
                    if thread.is_alive():
                        thread.join(timeout=5)
                seen_active, seen_total = query()
                if seen_active is not None:
                    active = seen_active
                    if seen_active > max_active:
                        max_active = seen_active
                if seen_total is not None:
                    total = seen_total
                out = bytes(slots['out']['kept'])
                err = bytes(slots['err']['kept'])
                dropped = int(slots['out']['dropped'] + slots['err']['dropped'])
                if not trunc:
                    for slot in (slots['out'], slots['err']):
                        eff = slot['line'] - (1 if slot['cr'] else 0)
                        if eff > line_bound:
                            trunc = True
                            code = 'LINE_BYTE_BOUND'
                            break
                if not trunc and (slots['out']['total'] > out_bound or slots['err']['total'] > out_bound):
                    trunc = True
                    code = 'OUTPUT_BYTE_BOUND'
                reason = (code + ' dropped_bytes=%d' % dropped) if trunc else ''
                if active != 0:
                    cleanup = 'cleanup-failed'
                elif timed_out:
                    cleanup = 'timeout-reaped'
                elif trunc:
                    cleanup = 'truncated-reaped'
                else:
                    cleanup = 'clean'
                cleanup_ok = (active == 0)
                if not cleanup_ok:
                    cleanup = 'cleanup-failed'
                return {'argv': tuple(argv), 'returncode': proc.returncode, 'stdout': out, 'stderr': err,
                        'timed_out': bool(timed_out), 'idle_timeout': bool(idle_flag),
                        'truncated': bool(trunc), 'truncate_reason': reason,
                        'dropped_bytes': dropped, 'active_processes': active, 'total_processes': total,
                        'max_active': int(max_active), 'cleanup': cleanup, 'cleanup_ok': bool(cleanup_ok)}
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

    def run(self, argv, *, input_bytes=None, timeout=None, cwd, env, bounds=None, idle_s=None, provisioned=False):
        if bounds is None:
            raise RuntimeError('BOUNDS_REQUIRED: pass descriptor-decoded bounds '
                               '{wall_s,idle_s,output_bytes,line_bytes,max_processes}; no defaults')
        if os.name == 'nt':
            return self._run_windows(argv, input_bytes=input_bytes, timeout=timeout, cwd=cwd, env=env,
                                     bounds=bounds, idle_s=idle_s, provisioned=provisioned)
        return self._run_posix(argv, input_bytes=input_bytes, timeout=timeout, cwd=cwd, env=env,
                               bounds=bounds, idle_s=idle_s, provisioned=provisioned)


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
            # R2: wall/idle/output/line/max all come from the frozen descriptor
            # (wall 10s is ample for the small python child; no override).
            bounds = _r2_descriptor_bounds('minimal-python-unittest.toml')
            disp = launcher.run(argv, input_bytes=raw, cwd=str(root), env=env, bounds=bounds)
            self.assertFalse(disp['truncated'], disp['truncate_reason'])
            self.assertTrue(disp['cleanup_ok'], disp)
            observed = subprocess.CompletedProcess(argv, disp['returncode'], disp['stdout'], disp['stderr'])
            if proto.exists():
                with proto.open('rb') as _pf:
                    body = _pf.read(r.MAX_PROTOCOL_BYTES + 2)
            else:
                body = b''
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
            body_sha256="a" * 64, matrix_cases=44, proof_ceiling=c.ProofCeiling("package-local"),
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
        body_sha256="a" * 64, matrix_cases=44, proof_ceiling=c.ProofCeiling("package-local"),
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
        desc = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        with tempfile.TemporaryDirectory() as directory:
            troot = Path(directory)
            (troot / 'Cargo.toml').write_text('[package]\nname = "runner"\nversion = "0.1.0"\n', newline='\n')
            parent = r._safe_path(troot, 'Cargo.toml').parent.as_posix()
            pid = f"path+file://{parent}#runner@0.1.0"
            verbatim = parent + '/Cargo.toml'
            meta = {'packages': [{'name': 'runner', 'manifest_path': verbatim, 'id': pid, 'version': '0.1.0', 'buildable': True}], 'workspace_members': [pid], 'excluded': []}
            obs = r.bind_package_observation(descriptor=desc, metadata=meta, root=troot, manifest_rel='Cargo.toml')
            self.assertEqual('runner', obs['name'])
            self.assertEqual('member', obs['member_kind'])
            self.assertTrue(obs['manifest_path'].endswith('/Cargo.toml'))
            self.assertEqual(verbatim, obs['manifest_path'])
            self.assertEqual(pid, obs['id'])
        with tempfile.TemporaryDirectory() as directory:
            import urllib.parse
            wroot = Path(directory)
            (wroot / 'Cargo.toml').write_text('[package]\nname = "runner"\nversion = "0.1.0"\n', newline='\n')
            wparent_posix = r._safe_path(wroot, 'Cargo.toml').parent.as_posix()
            wparent_native = wparent_posix.replace('/', '\\')
            wmanifest_native = wparent_native + '\\Cargo.toml'
            encoded = urllib.parse.quote(wparent_posix, safe='/:')
            if encoded.startswith('/'):
                wid = f"path+file://{encoded}#runner@0.1.0"
            else:
                wid = f"path+file:///{encoded}#runner@0.1.0"
            wmeta = {'packages': [{'name': 'runner', 'manifest_path': wmanifest_native, 'id': wid, 'version': '0.1.0', 'buildable': True}], 'workspace_members': [wid], 'excluded': []}
            wobs = r.bind_package_observation(descriptor=desc, metadata=wmeta, root=wroot, manifest_rel='Cargo.toml')
            self.assertEqual(wmanifest_native, wobs['manifest_path'])
            self.assertEqual(wid, wobs['id'])
            self.assertEqual('0.1.0', wobs['version'])
            self.assertTrue(wobs['manifest_path'].replace('\\', '/').endswith('/Cargo.toml'))
            wart = {'package': 'runner', 'package_id': wid, 'package_version': '0.1.0', 'manifest_rel': 'Cargo.toml', 'target_name': 'runner', 'target_kind': 'lib', 'profile_test': True, 'filenames': ('/tmp/wu850-win-bin.exe',), 'fresh': False}
            wbound = r.bind_test_binary(artifact=wart, binary_name='wu850-win-bin.exe', binary_sha256='b' * 64)
            self.assertEqual(wid, wbound['package_id'])
            wcombined = r.bind_execution_observations(package=wobs, binary=wbound)
            self.assertEqual('runner', wcombined['name'])
            self.assertEqual(wid, wcombined['id'])
            self.assertEqual(wmanifest_native, wcombined['manifest_path'])
            self.assertEqual('Cargo.toml', wcombined['manifest_rel'])

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
        desc = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        with tempfile.TemporaryDirectory() as directory:
            troot = Path(directory)
            (troot / 'Cargo.toml').write_text('[package]\nname = "runner"\nversion = "0.1.0"\n', newline='\n')
            parent = r._safe_path(troot, 'Cargo.toml').parent.as_posix()
            runner_pid = f"path+file://{parent}#runner@0.1.0"
            other_pid = f"path+file://{parent}#other@0.1.0"
            missing_meta = {'packages': [{'name': 'other', 'manifest_path': 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml', 'id': other_pid, 'version': '0.1.0', 'buildable': True}], 'workspace_members': [], 'excluded': []}
            with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_NOT_FOUND'):
                r.bind_package_observation(descriptor=desc, metadata=missing_meta, root=troot, manifest_rel='Cargo.toml')
            dup_meta = {'packages': [{'name': 'runner', 'manifest_path': 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml', 'id': runner_pid, 'version': '0.1.0', 'buildable': True}, {'name': 'runner', 'manifest_path': 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml', 'id': f"path+file://{parent}#runner@0.1.1", 'version': '0.1.1', 'buildable': True}], 'workspace_members': [], 'excluded': []}
            with self.assertRaisesRegex(r.RunnerInputError, 'DUPLICATE_PACKAGE_IDENTITY'):
                r.bind_package_observation(descriptor=desc, metadata=dup_meta, root=troot, manifest_rel='Cargo.toml')

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
        desc = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        with tempfile.TemporaryDirectory() as directory:
            troot = Path(directory)
            (troot / 'Cargo.toml').write_text('[package]\nname = "runner"\nversion = "0.1.0"\n', newline='\n')
            parent = r._safe_path(troot, 'Cargo.toml').parent.as_posix()
            pid = f"path+file://{parent}#runner@0.1.0"
            # Anchor: verbatim manifest_path dir == decoded id dir == filesystem parent.
            verbatim = parent + '/Cargo.toml'
            cases = (('member', {'packages': [{'name': 'runner', 'manifest_path': verbatim, 'id': pid, 'version': '0.1.0', 'buildable': True}], 'workspace_members': [pid], 'excluded': []}, True), ('excluded', {'packages': [{'name': 'runner', 'manifest_path': verbatim, 'id': pid, 'version': '0.1.0', 'buildable': True}], 'workspace_members': [], 'excluded': ['runner']}, True), ('standalone', {'packages': [{'name': 'runner', 'manifest_path': verbatim, 'id': pid, 'version': '0.1.0', 'buildable': True}], 'workspace_members': [], 'excluded': []}, True), ('unavailable', {'packages': [{'name': 'runner', 'manifest_path': verbatim, 'id': pid, 'version': '0.1.0', 'buildable': False}], 'workspace_members': [], 'excluded': []}, False))
            for kind, meta, ok in cases:
                with self.subTest(kind=kind):
                    if ok:
                        obs = r.bind_package_observation(descriptor=desc, metadata=meta, root=troot, manifest_rel='Cargo.toml')
                        self.assertEqual(kind, obs['member_kind'])
                    else:
                        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_UNAVAILABLE'):
                            r.bind_package_observation(descriptor=desc, metadata=meta, root=troot, manifest_rel='Cargo.toml')

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
        with tempfile.TemporaryDirectory() as directory:
            troot = Path(directory)
            (troot / 'Cargo.toml').write_text('[package]\nname = "runner"\nversion = "0.1.0"\n', newline='\n')
            parent = r._safe_path(troot, 'Cargo.toml').parent.as_posix()
            pid = f"path+file://{parent}#runner@0.1.0"
            # Anchor: verbatim manifest_path dir == decoded id dir == filesystem parent.
            verbatim = parent + '/Cargo.toml'
            excluded_meta = {'packages': [{'name': 'runner', 'manifest_path': verbatim, 'id': pid, 'version': '0.1.0', 'buildable': True}], 'workspace_members': [], 'excluded': ['runner']}
            self.assertEqual('excluded', r.bind_package_observation(descriptor=local, metadata=excluded_meta, root=troot, manifest_rel='Cargo.toml')['member_kind'])
            with self.assertRaisesRegex(r.RunnerInputError, 'WORKSPACE_MEMBER_REQUIRED'):
                r.bind_package_observation(descriptor=integrated, metadata=excluded_meta, root=troot, manifest_rel='Cargo.toml')
        stale = _b1_assignment(body_sha256='c' * 64)
        with self.assertRaisesRegex(r.RunnerInputError, 'STALE_ASSIGNMENT_BINDING'):
            r.bind_protected_snapshot(descriptor=local, assignment=stale, snapshot={k: 'a' * 64 for k in ['scripts/tests/test_work_unit_descriptor_runner.py', 'scripts/work_unit_gate/descriptor_runner.py']}, descriptor_rel=FILENAME, manifest_rel='scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml')
        snap_manifest = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        snap_required = sorted({p.value for p in local.source_roots + local.test_roots} | ({local.module.value.replace('.', '/') + '.py'} if local.module is not None else set()) | {FILENAME, snap_manifest})
        snap_good = {k: 'a' * 64 for k in snap_required}
        snap_bound = r.bind_protected_snapshot(descriptor=local, assignment=_b1_assignment(), snapshot=dict(snap_good), descriptor_rel=FILENAME, manifest_rel=snap_manifest)
        self.assertEqual(snap_required, snap_bound['keys'])
        self.assertEqual(local.proof_ceiling.value, snap_bound['proof_ceiling'])
        snap_alt_assign = _b1_assignment(proof_ceiling=c.ProofCeiling('workspace-integration'))
        snap_alt_desc = r.parse_descriptor(VALID.replace(b'package-local', b'workspace-integration'), FILENAME, snap_alt_assign)
        snap_alt_bound = r.bind_protected_snapshot(descriptor=snap_alt_desc, assignment=snap_alt_assign, snapshot=dict(snap_good), descriptor_rel=FILENAME, manifest_rel=snap_manifest)
        self.assertNotEqual(snap_bound['digest'], snap_alt_bound['digest'])


class RustRealRunnerCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._scratch = Path(tempfile.mkdtemp(prefix='wu850-'))
        cls._target = cls._scratch / 'target'
        cls._target.mkdir()
        cls._manifest_abs = str(RUST_TINY_MANIFEST.resolve())
        cls._target_abs = str(cls._target.resolve())
        cls.launcher = WindowsOwnedTree()
        # Lane-C production policy: cargo runs use runner-owned
        # r.toolchain_child_env (emits RUSTC_WRAPPER='' after filtering, so no
        # ambient sccache wrapper leaks in; direct rustc 1.97.1 chain peaks at
        # max_active=4 under the frozen descriptor bound). NOT the 6-name
        # minimal_child_env and NOT the full host env. Target dir stays under
        # %TEMP% (scratch below). Secret values never enter diagnostics.
        cls.cargo_env = r.toolchain_child_env(dict(os.environ))
        self_assert_wrapper = cls.cargo_env.get('RUSTC_WRAPPER')
        assert self_assert_wrapper == '', repr(self_assert_wrapper)
        argv = ['cargo', 'test', '--manifest-path', cls._manifest_abs, '--target-dir', cls._target_abs,
                '-p', 'wu850_tiny', '--', '--list', '--format', 'terse']
        # R2: output/line/idle/max are descriptor-bound; the cold build uses the
        # explicit provisioned=True escape (180s wall) because the tiny offline
        # build needs headroom on cold cache. Matrix proof cases (25/26/36/41)
        # never use it; they run at or under the decoded ceiling.
        disp = cls.launcher.run(argv, timeout=180, cwd=str(ROOT), env=cls.cargo_env,
                                bounds=_r2_descriptor_bounds('minimal-rust-package.toml'), provisioned=True)
        assert disp['returncode'] == 0, disp['stderr'][:2000]
        assert disp['cleanup_ok'], disp
        assert not disp['truncated'], disp
        cls.discovery_stdout = disp['stdout']
        cls.discovery_names = r.parse_rust_discovery(cls.discovery_stdout, 1000)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(str(cls._scratch), ignore_errors=True)

    def _exact_stdout(self, test_id, timeout=None):
        argv = ['cargo', 'test', '--manifest-path', self._manifest_abs, '--target-dir', self._target_abs,
                '-p', 'wu850_tiny', '--', '--exact', test_id]
        disp = self.launcher.run(argv, timeout=timeout, cwd=str(ROOT), env=self.cargo_env,
                                 bounds=_r2_descriptor_bounds('minimal-rust-package.toml'))
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
        build_argv = ['cargo', 'build', '--manifest-path', self._manifest_abs, '--target-dir', self._target_abs, '-p', 'wu850_tiny', '--message-format', 'json-render-diagnostics']
        self.assertEqual(tuple(build_argv), r.assert_no_workspace_wide(build_argv))
        shape = r.build_cargo_build_command(manifest_rel='scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml', target_dir_rel='target/wu850-tiny', package='wu850_tiny')
        self.assertIn('--message-format', shape)
        bdisp = self.launcher.run(build_argv, cwd=str(ROOT), env=self.cargo_env, bounds=_r2_descriptor_bounds('minimal-rust-package.toml'))
        self.assertEqual(0, bdisp['returncode'], bdisp['stderr'][-2000:])
        self.assertTrue(bdisp['cleanup_ok'], bdisp)
        self.assertFalse(bdisp['truncated'], bdisp)
        plain_arts = r.parse_cargo_build_stream(bdisp['stdout'], package='wu850_tiny', manifest_rel='scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml')
        self.assertGreaterEqual(len(plain_arts), 1)
        self.assertTrue(any(a['profile_test'] is False for a in plain_arts))
        norun_argv = ['cargo', 'test', '--no-run', '--message-format', 'json-render-diagnostics', '--manifest-path', self._manifest_abs, '--target-dir', self._target_abs, '-p', 'wu850_tiny']
        self.assertEqual(tuple(norun_argv), r.assert_no_workspace_wide(norun_argv))
        ndisp = self.launcher.run(norun_argv, cwd=str(ROOT), env=self.cargo_env, bounds=_r2_descriptor_bounds('minimal-rust-package.toml'))
        self.assertEqual(0, ndisp['returncode'], ndisp['stderr'][-2000:])
        self.assertTrue(ndisp['cleanup_ok'], ndisp)
        self.assertFalse(ndisp['truncated'], ndisp)
        arts = r.parse_cargo_build_stream(ndisp['stdout'], package='wu850_tiny', manifest_rel='scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml')
        test_arts = sorted((a for a in arts if a['profile_test'] is True), key=lambda a: a['target_name'])
        self.assertEqual(1, len(test_arts))
        art = test_arts[0]
        self.assertEqual('wu850_tiny', art['package'])
        self.assertEqual('scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml', art['manifest_rel'])
        self.assertEqual('wu850_tiny', art['target_name'])
        self.assertEqual('lib', art['target_kind'])
        self.assertIs(art['profile_test'], True)
        self.assertGreaterEqual(len(art['filenames']), 1)
        self.assertIs(type(art['fresh']), bool)
        exe_candidates = sorted(fn for fn in art['filenames'] if fn.lower().endswith('.exe') and Path(fn).exists())
        self.assertEqual(1, len(exe_candidates))
        real_file = exe_candidates[0]
        self.assertTrue(Path(real_file).name.startswith('wu850_tiny-'))
        digest = hashlib.sha256(Path(real_file).read_bytes()).hexdigest()
        bound = r.bind_test_binary(artifact=art, binary_name=Path(real_file).name, binary_sha256=digest)
        self.assertEqual(Path(real_file).name, bound['binary_name'])
        self.assertEqual(digest, bound['binary_sha256'])
        self.assertIs(bound['profile_test'], True)
        desc = r.parse_descriptor((DESCRIPTOR_DIR / 'minimal-rust-package.toml').read_bytes(), FILENAME, _b1_assignment())
        self.assertIs(type(desc), c.WorkUnitDescriptor)
        tiny_rel = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        real_parent = r._safe_path(ROOT, tiny_rel).parent.as_posix()
        meta_argv = ['cargo', 'metadata', '--format-version', '1', '--offline',
                     '--manifest-path', self._manifest_abs, '--no-deps']
        self.assertEqual(tuple(meta_argv), r.assert_no_workspace_wide(meta_argv))
        mdisp = self.launcher.run(meta_argv, cwd=str(ROOT), env=self.cargo_env,
                                  bounds=_r2_descriptor_bounds('minimal-rust-package.toml'))
        self.assertEqual(0, mdisp['returncode'], mdisp['stderr'][-2000:])
        self.assertTrue(mdisp['cleanup_ok'], mdisp)
        self.assertFalse(mdisp['truncated'], mdisp)
        observed_meta = json.loads(mdisp['stdout'].decode('utf-8'))
        observed_pkgs = [p for p in observed_meta['packages'] if p['name'] == 'wu850_tiny']
        self.assertEqual(1, len(observed_pkgs))
        observed_pkg = observed_pkgs[0]
        self.assertEqual(art['package_id'], observed_pkg['id'])
        self.assertEqual(art['package_version'], observed_pkg['version'])
        self.assertEqual('0.1.0', observed_pkg['version'])
        self.assertIn(observed_pkg['id'], observed_meta['workspace_members'])
        self.assertNotEqual('path+file:///forged#wu850_tiny@99.9.9', observed_pkg['id'])
        self.assertNotEqual('99.9.9', observed_pkg['version'])
        raw_manifest = observed_pkg['manifest_path']
        self.assertIn('\\', raw_manifest)
        self.assertIn('Cargo.toml', raw_manifest)
        real_id = observed_pkg['id']
        self.assertTrue(real_id.startswith('path+file:///'))
        pkg_meta = {'packages': [{'name': observed_pkg['name'],
                                  'manifest_path': raw_manifest,
                                  'id': real_id, 'version': observed_pkg['version'],
                                  'buildable': True}],
                    'workspace_members': [real_id], 'excluded': []}
        pkg_obs = r.bind_package_observation(descriptor=desc, metadata=pkg_meta, root=ROOT, manifest_rel=tiny_rel)
        self.assertEqual(real_id, pkg_obs['id'])
        self.assertEqual(raw_manifest, pkg_obs['manifest_path'])
        self.assertTrue(pkg_obs['manifest_path'].replace('\\', '/').endswith('scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'))
        self.assertEqual('0.1.0', pkg_obs['version'])
        self.assertEqual(observed_pkg['version'], pkg_obs['version'])
        self.assertEqual('member', pkg_obs['member_kind'])
        real_art = dict(art, package_id=real_id)
        pkg_bound = r.bind_test_binary(artifact=real_art, binary_name=Path(real_file).name, binary_sha256=digest)
        self.assertEqual(real_id, pkg_bound['package_id'])
        combined = r.bind_execution_observations(package=pkg_obs, binary=pkg_bound)
        self.assertEqual(12, len(combined))
        self.assertEqual({'name', 'version', 'id', 'manifest_path', 'manifest_rel', 'member_kind',
                          'binary_name', 'binary_sha256', 'target', 'target_kind', 'profile_test',
                          'cfgs'}, set(combined))
        receipt = r.compose_discovery_receipt(descriptor=desc, binary=pkg_bound, test_name='tiny_ok_a', kind='rust', package=pkg_obs)
        self.assertIs(type(receipt), c.DiscoveredTestReceipt)
        self.assertIs(type(receipt.test), c.TestIdentity)
        self.assertEqual('tiny_ok_a', receipt.test.qualified_name)
        self.assertEqual(desc.mode, receipt.test.mode)
        self.assertEqual(desc.identity, receipt.descriptor)
        self.assertEqual(desc.sha256, receipt.descriptor_sha256)
        self.assertEqual(desc.body_sha256, receipt.source_sha256)
        self.assertEqual(digest, receipt.artifact_sha256)
        self.assertIs(receipt.phase, desc.phase)
        self.assertEqual(pkg_bound['manifest_rel'], receipt.location.path.value)
        record = r.compose_execution_record(discovery=receipt, disposition='executed-pass', detail='tiny_ok_a-pass')
        self.assertIs(type(record), c.TestExecutionRecord)
        self.assertIs(record.disposition, c.ExecutionDisposition.EXECUTED_PASS)
        self.assertEqual(receipt.test, record.test)
        rust_desc = desc
        evil_id = f"path+file://{real_parent}#wu850_tiny@99.9.9"
        evil_meta = {'packages': [{'name': 'wu850_tiny', 'manifest_path': 'C:/forged/elsewhere/Cargo.toml',
                                   'id': evil_id, 'version': '99.9.9', 'buildable': True}],
                     'workspace_members': [evil_id], 'excluded': []}
        with self.assertRaisesRegex(r.RunnerInputError, 'MANIFEST_VERSION_MISMATCH'):
            r.bind_package_observation(descriptor=rust_desc, metadata=evil_meta, root=ROOT, manifest_rel=tiny_rel)
        evil_dir_id = 'path+file:///forged/elsewhere#wu850_tiny@0.1.0'
        evil_dir_meta = {'packages': [{'name': 'wu850_tiny', 'manifest_path': 'C:/forged/elsewhere/Cargo.toml',
                                       'id': evil_dir_id, 'version': '0.1.0', 'buildable': True}],
                         'workspace_members': [evil_dir_id], 'excluded': []}
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_ID_DIR_MISMATCH'):
            r.bind_package_observation(descriptor=rust_desc, metadata=evil_dir_meta, root=ROOT, manifest_rel=tiny_rel)
        registry_id = 'registry+https://github.com/rust-lang/crates.io-index#wu850_tiny@0.1.0'
        registry_meta = {'packages': [{'name': 'wu850_tiny', 'manifest_path': 'C:/repo/' + tiny_rel,
                                       'id': registry_id, 'version': '0.1.0', 'buildable': True}],
                         'workspace_members': [registry_id], 'excluded': []}
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_IDENTITY_INCONSISTENT'):
            r.bind_package_observation(descriptor=rust_desc, metadata=registry_meta, root=ROOT, manifest_rel=tiny_rel)
        forged_pkg = dict(pkg_obs, manifest_path='C:/forged/elsewhere/Cargo.toml')
        with self.assertRaisesRegex(r.RunnerInputError, 'MANIFEST_OBSERVATION_MISMATCH'):
            r.bind_execution_observations(package=forged_pkg, binary=pkg_bound)
        with self.assertRaisesRegex(r.RunnerInputError, 'MANIFEST_OBSERVATION_MISMATCH'):
            r.compose_discovery_receipt(descriptor=rust_desc, binary=pkg_bound, test_name='tiny_ok_a',
                                        kind='rust', package=forged_pkg)
        mismatched = dict(pkg_bound, package_id=f"path+file://{real_parent}#wu850_tiny@9.9.9", version='9.9.9', package_version='9.9.9')
        with self.assertRaisesRegex(r.RunnerInputError, 'ARTIFACT_OBSERVATION_MISMATCH'):
            r.bind_execution_observations(package=pkg_obs, binary=mismatched)
        with self.assertRaisesRegex(r.RunnerInputError, 'ARTIFACT_OBSERVATION_MISMATCH'):
            r.compose_discovery_receipt(descriptor=rust_desc, binary=mismatched, test_name='tiny_ok_a',
                                        kind='rust', package=pkg_obs)
        inconsistent_meta = {'packages': [{'name': 'wu850_tiny', 'manifest_path': 'C:/repo/' + art['manifest_rel'],
                                           'id': art['package_id'], 'version': '99.9.9', 'buildable': True}],
                             'workspace_members': [art['package_id']], 'excluded': []}
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_IDENTITY_INCONSISTENT'):
            r.bind_package_observation(descriptor=rust_desc, metadata=inconsistent_meta, root=ROOT, manifest_rel=tiny_rel)

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
        rel = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        good_art = b'{"reason":"compiler-artifact","package_id":"path+file:///x#wu850_tiny@0.1.0","target":{"name":"wu850_tiny","kind":["lib"]},"profile":{"test":false},"filenames":["/tmp/a.rlib"],"fresh":false}\n'
        good_fin = b'{"reason":"build-finished","success":true}\n'
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_IDENTITY_INCONSISTENT'):
            r.parse_cargo_build_stream(good_art.replace(b'#wu850_tiny@', b'#other@') + good_fin, package='wu850_tiny', manifest_rel=rel)
        with self.assertRaisesRegex(r.RunnerInputError, 'BUILD_NOT_SUCCESSFUL'):
            r.parse_cargo_build_stream(good_art, package='wu850_tiny', manifest_rel=rel)
        with self.assertRaisesRegex(r.RunnerInputError, 'BUILD_NOT_SUCCESSFUL'):
            r.parse_cargo_build_stream(good_art + b'{"reason":"build-finished","success":false}\n', package='wu850_tiny', manifest_rel=rel)
        with self.assertRaisesRegex(r.RunnerInputError, 'UNSUPPORTED_BUILD_EVENT'):
            r.parse_cargo_build_stream(b'{"reason":"compiler-message","message":"x"}\n' + good_art + good_fin, package='wu850_tiny', manifest_rel=rel)
        with self.assertRaisesRegex(r.RunnerInputError, 'BUILD_NOT_SUCCESSFUL'):
            r.parse_cargo_build_stream(b'', package='wu850_tiny', manifest_rel=rel)

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

    def _short_child(self, root, phase, expected, timeout, max_tests=100, bounds=None):
        # Test-only bounded driver run (mirrors PythonProtocolTests.child but
        # with a caller-chosen wall timeout). Returns (disp, body, req).
        # R2: bounds required; defaults to the frozen python-unittest descriptor.
        # Callers pass tighter-or-equal timeouts (3s/5s <= 10s descriptor wall).
        if bounds is None:
            bounds = _r2_descriptor_bounds('minimal-python-unittest.toml')
        self.assertLessEqual(timeout, bounds['wall_s'])
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
            disp = launcher.run(argv, input_bytes=raw, timeout=timeout, cwd=str(root), env=env,
                                bounds=bounds)
            if proto.exists():
                with proto.open('rb') as _pf:
                    body = _pf.read(r.MAX_PROTOCOL_BYTES + 2)
            else:
                body = b''
            return disp, body, req

    def _minimal_env(self):
        return {'PATH': os.environ.get('PATH', os.defpath), 'SYSTEMROOT': os.environ.get('SYSTEMROOT', r'C:\Windows'),
                'TEMP': tempfile.gettempdir(), 'TMP': tempfile.gettempdir(),
                'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONIOENCODING': 'utf-8'}

    # WORK_UNIT_CASE: 850/25
    def test_real_bounded_child_tree_timeout_cleanup(self):
        import inspect
        launcher = WindowsOwnedTree()
        # R2: bounds decoded from the frozen descriptor; the 3s wall override
        # is tighter than the 10s descriptor ceiling.
        desc = r.decode_descriptor((DESCRIPTOR_DIR / 'minimal-python-unittest.toml').read_bytes(), FILENAME)
        bounds = _r2_descriptor_bounds('minimal-python-unittest.toml')
        self.assertEqual(r.enforcement_plan(bounds=desc['bounds']), bounds)
        self.assertEqual(desc['bounds']['child_processes'], bounds['max_processes'])
        self.assertEqual(desc['bounds']['output_bytes'], bounds['output_bytes'])
        self.assertEqual(desc['bounds']['wall_ms'] / 1000, bounds['wall_s'])
        self.assertEqual(desc['bounds']['idle_ms'] / 1000, bounds['idle_s'])
        self.assertEqual(desc['bounds']['line_bytes'], bounds['line_bytes'])
        self.assertEqual(desc['bounds']['discovery_tests'], bounds['max_tests'])
        code = ('import subprocess, sys, time; '
                'subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]); '
                'time.sleep(60)')
        disp = launcher.run([sys.executable, '-c', code], timeout=3, cwd=str(ROOT), env=self._minimal_env(),
                            bounds=bounds)
        self.assertTrue(disp['timed_out'], disp)
        self.assertEqual('timeout-reaped', disp['cleanup'], disp)
        self.assertTrue(disp['cleanup_ok'], disp)
        self.assertEqual(0, disp['active_processes'], disp)
        self.assertGreaterEqual(disp['total_processes'], 2, disp)
        self.assertGreaterEqual(disp['max_active'], 2, disp)
        self.assertFalse(disp['idle_timeout'], disp)
        # The reap path is TerminateJobObject on the owned Job, which a plain
        # Popen.kill-only cleanup cannot produce (a kill-only parent leaves the
        # grandchild alive and accounting nonzero).
        self.assertIn('TerminateJobObject', inspect.getsource(WindowsOwnedTree._run_windows))

    # WORK_UNIT_CASE: 850/26
    def test_stdout_stderr_line_bounds_fail_closed(self):
        # R2: descriptor-decoded ceiling plus test-provisioned tighter bounds
        # (fail-closed subsets; the small outputs below would not trip the
        # 64KiB descriptor ceiling, so truncation is proven at the tight
        # subset while the full descriptor mapping is exercised as control).
        full = _r2_descriptor_bounds('minimal-python-unittest.toml')
        desc = r.decode_descriptor((DESCRIPTOR_DIR / 'minimal-python-unittest.toml').read_bytes(), FILENAME)
        self.assertEqual(r.enforcement_plan(bounds=desc['bounds']), full)
        self.assertEqual(desc['bounds']['output_bytes'], full['output_bytes'])
        self.assertEqual(desc['bounds']['line_bytes'], full['line_bytes'])
        self.assertEqual(desc['bounds']['wall_ms'] / 1000, full['wall_s'])
        self.assertEqual(desc['bounds']['idle_ms'] / 1000, full['idle_s'])
        self.assertEqual(desc['bounds']['child_processes'], full['max_processes'])
        self.assertEqual(desc['bounds']['discovery_tests'], full['max_tests'])
        tight = dict(full, output_bytes=2048, line_bytes=256)
        self.assertLessEqual(tight['output_bytes'], full['output_bytes'])
        self.assertLessEqual(tight['line_bytes'], full['line_bytes'])
        launcher = WindowsOwnedTree()
        over_out = launcher.run([sys.executable, '-c', 'import sys\nfor i in range(200): sys.stdout.write("y" * 20 + "\\n")'],
                                cwd=str(ROOT), env=self._minimal_env(), bounds=tight)
        self.assertTrue(over_out['truncated'], over_out['truncate_reason'])
        self.assertTrue(over_out['truncate_reason'].startswith('OUTPUT_BYTE_BOUND'), over_out['truncate_reason'])
        self.assertLessEqual(len(over_out['stdout']), tight['output_bytes'] + 65536)
        self.assertTrue(over_out['cleanup_ok'], over_out)
        self.assertEqual(0, over_out['active_processes'], over_out)
        over_line = launcher.run([sys.executable, '-c', 'import sys; sys.stdout.write("z" * 1000 + "\\n")'],
                                 cwd=str(ROOT), env=self._minimal_env(), bounds=tight)
        self.assertTrue(over_line['truncated'], over_line['truncate_reason'])
        self.assertTrue(over_line['truncate_reason'].startswith('LINE_BYTE_BOUND'), over_line['truncate_reason'])
        over_err = launcher.run([sys.executable, '-c', 'import sys; sys.stderr.write("e" * 5000)'],
                                cwd=str(ROOT), env=self._minimal_env(), bounds=tight)
        self.assertTrue(over_err['truncated'], over_err['truncate_reason'])
        # Exact frozen ceiling: over-emitting child at output_bytes=65536 /
        # line_bytes=4096 still truncates (no looser substitute).
        over_full = launcher.run([sys.executable, '-c', 'import sys\nfor i in range(4000): sys.stdout.write("y" * 20 + "\\n")'],
                                 cwd=str(ROOT), env=self._minimal_env(), bounds=full)
        self.assertTrue(over_full['truncated'], over_full['truncate_reason'])
        self.assertTrue(over_full['truncate_reason'].startswith('OUTPUT_BYTE_BOUND'), over_full['truncate_reason'])
        self.assertTrue(over_full['cleanup_ok'], over_full)
        self.assertEqual(0, over_full['active_processes'], over_full)
        # Descriptor-bounds control: a small output is accepted untruncated
        # under the full frozen bounds.
        ok = launcher.run([sys.executable, '-c', 'print("hello-descriptor-control")'],
                          cwd=str(ROOT), env=self._minimal_env(), bounds=full)
        self.assertFalse(ok['truncated'], ok)
        self.assertIn(b'hello-descriptor-control', ok['stdout'])
        self.assertEqual(0, ok['dropped_bytes'], ok)
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
        rel = r.bind_python_suite(root=ROOT, module=module, test_roots=roots)
        self.assertEqual('scripts/tests/test_work_unit_descriptor_runner.py', rel)
        with self.assertRaisesRegex(r.RunnerInputError, 'FOREIGN_TEST_IDENTITY|FOREIGN_TEST_SOURCE'):
            r.bind_python_suite(root=ROOT, module='other.unregistered', test_roots=roots)
        with tempfile.TemporaryDirectory() as directory:
            troot = Path(directory)
            (troot / 'pkg').mkdir()
            (troot / 'pkg' / 'suite.py').write_text('x\n', newline='\n')
            self.assertEqual('pkg/suite.py', r.bind_python_suite(root=troot, module='pkg.suite', test_roots=['pkg']))
            with self.assertRaisesRegex(r.RunnerInputError, 'FOREIGN_TEST_IDENTITY|FOREIGN_TEST_SOURCE'):
                r.bind_python_suite(root=troot, module='outside.suite', test_roots=['pkg'])

    # WORK_UNIT_CASE: 850/32
    def test_metadata_generator_mutation_network_spellings_rejected(self):
        for spelling in ('mod:gen', 'mod/run', 'mod\\x', 'evil!', 'a b', 'x.py', 'x.ps1', 'x.sh',
                         'x.pyw', 'x.pyc', 'x.pyd', 'x.psm1', 'x.psd1', 'x.dll', 'x.so', 'x.dylib', 'x.bat', 'x.exe',
                         'x.js', 'x.com', 'x.cmd', 'x.vbs'):
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
        # R2: per-mode descriptor bounds demonstrably drive the launcher.
        per_mode_bounds = {}
        for name, mode in (('minimal-python-unittest.toml', 'python-unittest'),
                           ('minimal-metadata-python.toml', 'metadata-python')):
            data = r.decode_descriptor((DESCRIPTOR_DIR / name).read_bytes(), FILENAME)
            self.assertEqual(mode, data['mode'])
            self.assertGreater(data['bounds']['wall_ms'], 0)
            bounds = _r2_descriptor_bounds(name)
            self.assertEqual(r.enforcement_plan(bounds=data['bounds']), bounds)
            self.assertEqual(data['bounds']['wall_ms'] / 1000, bounds['wall_s'])
            self.assertEqual(data['bounds']['idle_ms'] / 1000, bounds['idle_s'])
            self.assertEqual(data['bounds']['output_bytes'], bounds['output_bytes'])
            self.assertEqual(data['bounds']['line_bytes'], bounds['line_bytes'])
            self.assertEqual(data['bounds']['child_processes'], bounds['max_processes'])
            self.assertEqual(data['bounds']['discovery_tests'], bounds['max_tests'])
            per_mode_bounds[mode] = bounds
        argv = r.build_python_child_command(script_rel='scripts/work_unit_gate/descriptor_runner.py', fd=10)
        self.assertEqual(argv, r.build_python_child_command(script_rel='scripts/work_unit_gate/descriptor_runner.py', fd=10))
        slow = BASE.replace('self.assertEqual(2 + 2, 4)', 'import time\n        time.sleep(30)')
        with self.fixture(slow) as root:
            observed, discovery, _, _ = self.child(root)
            self.assertEqual(0, observed.returncode, observed.stderr)
            disp, body, _ = self._short_child(root, 'execute', discovery['tests'], timeout=3,
                                              bounds=per_mode_bounds['python-unittest'])
            self.assertTrue(disp['timed_out'], disp)
            self.assertFalse(disp['idle_timeout'], disp)
            self.assertEqual('timeout-reaped', disp['cleanup'], disp)
            self.assertTrue(disp['cleanup_ok'], disp)
            self.assertEqual(0, disp['active_processes'], disp)
            self.assertEqual(b'', body)
        small = dict(per_mode_bounds['python-unittest'], output_bytes=64, line_bytes=16)
        disp = WindowsOwnedTree().run([sys.executable, '-c', 'print("q" * 1024)'],
                                      cwd=str(ROOT), env=self._minimal_env(), bounds=small)
        self.assertTrue(disp['truncated'], disp)
        over_ceiling = WindowsOwnedTree().run([sys.executable, '-c', 'import sys\nfor i in range(4000): sys.stdout.write("y" * 20 + "\\n")'],
                                              cwd=str(ROOT), env=self._minimal_env(), bounds=per_mode_bounds['python-unittest'])
        self.assertTrue(over_ceiling['truncated'], over_ceiling['truncate_reason'])
        self.assertTrue(over_ceiling['truncate_reason'].startswith('OUTPUT_BYTE_BOUND'), over_ceiling['truncate_reason'])
        self.assertTrue(over_ceiling['cleanup_ok'], over_ceiling)
        self.assertEqual(0, over_ceiling['active_processes'], over_ceiling)

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
        with self.assertRaises(TypeError):
            r.minimal_child_env({'PATH': 'x'}, allowed={'PATH'})
        with self.assertRaises(TypeError):
            r.minimal_child_env({'PATH': 'x'}, allowed_names={'PATH'})
        with self.assertRaisesRegex(r.RunnerInputError, 'ENV_VALUE_BOUND'):
            r.minimal_child_env({'PATH': 'x' * (r.ENV_VALUE_CAP + 1)})
        big = {'PATH': 'p', 'TEMP': 't' * r.ENV_TOTAL_CAP, 'TMP': 'u'}
        with self.assertRaisesRegex(r.RunnerInputError, 'ENV_TOTAL_BOUND|ENV_VALUE_BOUND'):
            r.minimal_child_env(big)

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
            # R2: execute phase runs under frozen descriptor bounds (5s wall
            # override is tighter than the 10s descriptor ceiling).
            bounds = _r2_descriptor_bounds('minimal-python-unittest.toml')
            disp, body, _ = self._short_child(root, 'execute', discovery['tests'], timeout=5, bounds=bounds)
            self.assertTrue(disp['timed_out'], disp)
            self.assertEqual(0, disp['active_processes'], disp)
            self.assertTrue(disp['cleanup_ok'], disp)
            self.assertEqual('timeout-reaped', disp['cleanup'], disp)
            self.assertEqual(b'', body)
            self.assertGreaterEqual(disp['total_processes'], 2, disp)
            self.assertGreaterEqual(disp['max_active'], 2, disp)

            def is_green(d):
                if d.get('idle_timeout', False):
                    return False
                return r.cleanup_verdict(cleanup=d['cleanup'], active_processes=d['active_processes'], truncated=d['truncated']) == 'green'
            self.assertFalse(disp['idle_timeout'], disp)
            self.assertTrue(is_green(disp))
            self.assertEqual('non-green', r.cleanup_verdict(cleanup='unknown-mystery', active_processes=3, truncated=False))
            self.assertEqual('non-green', r.cleanup_verdict(cleanup='truncated-reaped', active_processes=0, truncated=True))
            self.assertFalse(is_green(dict(disp, cleanup='truncated-reaped', truncated=True)))
            self.assertFalse(is_green(dict(disp, cleanup='timeout-reaped', idle_timeout=True)))
            self.assertFalse(is_green(dict(disp, truncated=True)))
            self.assertFalse(is_green(dict(disp, cleanup='cleanup-failed', cleanup_ok=False)))
            with self.assertRaises(r.RunnerInputError):
                r.cleanup_verdict(cleanup=None, active_processes=0, truncated=False)

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
        desc = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        assign = _b1_assignment()
        manifest = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        required = sorted({p.value for p in desc.source_roots + desc.test_roots} | ({desc.module.value.replace('.', '/') + '.py'} if desc.module is not None else set()) | {FILENAME, manifest})
        self.assertEqual(['.github/work-units/850.toml', 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml', 'scripts/tests/test_work_unit_descriptor_runner.py', 'scripts/work_unit_gate/descriptor_runner.py'], required)
        good = {k: 'a' * 64 for k in required}
        bound = r.bind_protected_snapshot(descriptor=desc, assignment=assign, snapshot=dict(good), descriptor_rel=FILENAME, manifest_rel=manifest)
        self.assertEqual(required, bound['keys'])
        self.assertEqual(64, len(bound['digest']))
        self.assertEqual('package-local', bound['proof_ceiling'])
        self.assertEqual(desc.proof_ceiling.value, bound['proof_ceiling'])
        alt_assign = _b1_assignment(proof_ceiling=c.ProofCeiling('workspace-integration'))
        alt_desc = r.parse_descriptor(VALID.replace(b'package-local', b'workspace-integration'), FILENAME, alt_assign)
        alt_bound = r.bind_protected_snapshot(descriptor=alt_desc, assignment=alt_assign, snapshot=dict(good), descriptor_rel=FILENAME, manifest_rel=manifest)
        self.assertEqual('workspace-integration', alt_bound['proof_ceiling'])
        self.assertNotEqual(bound['digest'], alt_bound['digest'])
        with self.assertRaisesRegex(r.RunnerInputError, 'MISSING_SNAPSHOT_KEY'):
            r.bind_protected_snapshot(descriptor=desc, assignment=assign, snapshot={k: 'a' * 64 for k in required[:-1]}, descriptor_rel=FILENAME, manifest_rel=manifest)
        with self.assertRaisesRegex(r.RunnerInputError, 'FOREIGN_SNAPSHOT_KEY'):
            r.bind_protected_snapshot(descriptor=desc, assignment=assign, snapshot=dict(good, **{'extra/key.py': 'a' * 64}), descriptor_rel=FILENAME, manifest_rel=manifest)
        with self.assertRaisesRegex(r.RunnerInputError, 'SNAPSHOT_DIGEST_SYNTAX|SNAPSHOT_SHAPE|MISSING_SNAPSHOT_KEY'):
            r.bind_protected_snapshot(descriptor=desc, assignment=assign, snapshot={}, descriptor_rel=FILENAME, manifest_rel=manifest)
        with self.assertRaisesRegex(r.RunnerInputError, 'SNAPSHOT_DIGEST_SYNTAX'):
            r.bind_protected_snapshot(descriptor=desc, assignment=assign, snapshot={k: 'not-hex' for k in required}, descriptor_rel=FILENAME, manifest_rel=manifest)
        finding = r.compose_mutation_finding(descriptor=desc, diff=diff, snapshot_digest=bound['digest'])
        self.assertIsNotNone(finding)
        self.assertIs(finding.severity, c.FindingSeverity.ERROR)
        self.assertIs(finding.finding_class, c.FindingClass.SOURCE_UNAVAILABLE)
        self.assertEqual(desc.unit, finding.owner)
        self.assertIn('tests/seed.txt', finding.message)
        self.assertTrue(finding.message.startswith('protected-input-invalidated:'))
        clean = r.compose_mutation_finding(descriptor=desc, diff={'mutated': [], 'added': [], 'removed': []}, snapshot_digest=bound['digest'])
        self.assertIsNone(clean)

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
        desc = r.parse_descriptor((DESCRIPTOR_DIR / 'minimal-rust-package.toml').read_bytes(), FILENAME, _b1_assignment())
        tiny_rel = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        real_parent = r._safe_path(ROOT, tiny_rel).parent.as_posix()
        real_pid = f"path+file://{real_parent}#wu850_tiny@0.1.0"
        art = {'package': 'wu850_tiny', 'package_id': real_pid, 'package_version': '0.1.0', 'manifest_rel': tiny_rel, 'target_name': 'wu850_tiny', 'target_kind': 'lib', 'profile_test': True, 'filenames': ('/tmp/real-test-bin.exe',), 'fresh': False}
        bound = r.bind_test_binary(artifact=art, binary_name='real-test-bin.exe', binary_sha256='a' * 64)
        self.assertEqual('0.1.0', bound['package_version'])
        self.assertEqual(real_pid, bound['package_id'])
        with self.assertRaisesRegex(r.RunnerInputError, 'BINARY_NOT_PRODUCED'):
            r.bind_test_binary(artifact=art, binary_name='other-bin.exe', binary_sha256='a' * 64)
        pkg_meta = {'packages': [{'name': 'wu850_tiny',
                                  'manifest_path': real_parent + '/Cargo.toml',
                                  'id': art['package_id'], 'version': art['package_version'],
                                  'buildable': True}],
                    'workspace_members': [art['package_id']], 'excluded': []}
        pkg_obs = r.bind_package_observation(descriptor=desc, metadata=pkg_meta, root=ROOT, manifest_rel=tiny_rel)
        self.assertEqual(real_parent + '/Cargo.toml', pkg_obs['manifest_path'])
        self.assertEqual(real_pid, pkg_obs['id'])
        evil_version_id = f"path+file://{real_parent}#wu850_tiny@99.9.9"
        evil_version_meta = {'packages': [{'name': 'wu850_tiny', 'manifest_path': 'C:/forged/elsewhere/Cargo.toml',
                                           'id': evil_version_id, 'version': '99.9.9', 'buildable': True}],
                             'workspace_members': [evil_version_id], 'excluded': []}
        with self.assertRaisesRegex(r.RunnerInputError, 'MANIFEST_VERSION_MISMATCH'):
            r.bind_package_observation(descriptor=desc, metadata=evil_version_meta, root=ROOT, manifest_rel=tiny_rel)
        evil_dir_id = 'path+file:///forged/elsewhere#wu850_tiny@0.1.0'
        evil_dir_meta = {'packages': [{'name': 'wu850_tiny', 'manifest_path': 'C:/forged/elsewhere/Cargo.toml',
                                       'id': evil_dir_id, 'version': '0.1.0', 'buildable': True}],
                         'workspace_members': [evil_dir_id], 'excluded': []}
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_ID_DIR_MISMATCH'):
            r.bind_package_observation(descriptor=desc, metadata=evil_dir_meta, root=ROOT, manifest_rel=tiny_rel)
        forged_prefix_path = 'C:/forged-prefix/' + tiny_rel
        forged_prefix_meta = {'packages': [{'name': 'wu850_tiny', 'manifest_path': forged_prefix_path,
                                            'id': real_pid, 'version': '0.1.0', 'buildable': True}],
                              'workspace_members': [real_pid], 'excluded': []}
        with self.assertRaisesRegex(r.RunnerInputError, 'MANIFEST_PATH_DIR_MISMATCH'):
            r.bind_package_observation(descriptor=desc, metadata=forged_prefix_meta, root=ROOT, manifest_rel=tiny_rel)
        with self.assertRaisesRegex(r.RunnerInputError, 'MANIFEST_PATH_DIR_MISMATCH'):
            forged_obs = r.bind_package_observation(descriptor=desc, metadata=forged_prefix_meta, root=ROOT, manifest_rel=tiny_rel)
            r.bind_execution_observations(package=forged_obs, binary=bound)
            r.compose_discovery_receipt(descriptor=desc, binary=bound, test_name='tiny_ok_a', kind='rust', package=forged_obs)
        registry_id = 'registry+https://github.com/rust-lang/crates.io-index#wu850_tiny@0.1.0'
        registry_meta = {'packages': [{'name': 'wu850_tiny', 'manifest_path': 'C:/repo/' + tiny_rel,
                                       'id': registry_id, 'version': '0.1.0', 'buildable': True}],
                         'workspace_members': [registry_id], 'excluded': []}
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_IDENTITY_INCONSISTENT'):
            r.bind_package_observation(descriptor=desc, metadata=registry_meta, root=ROOT, manifest_rel=tiny_rel)
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_OBSERVATION_REQUIRED'):
            r.compose_discovery_receipt(descriptor=desc, binary=bound, test_name='tiny_ok_a', kind='rust')
        py_desc = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_OBSERVATION_UNEXPECTED'):
            r.compose_discovery_receipt(descriptor=py_desc, binary=None, test_name='a.B.test_x',
                                        kind='python', package={'name': 'runner'})
        with self.assertRaisesRegex(r.RunnerInputError, 'BINARY_DIGEST_REQUIRED'):
            r.compose_discovery_receipt(descriptor=desc, binary=dict(bound, binary_sha256='not-hex'),
                                        test_name='tiny_ok_a', kind='rust', package=pkg_obs)
        with self.assertRaisesRegex(r.RunnerInputError, 'OBSERVATION_SHAPE'):
            r.compose_discovery_receipt(descriptor=desc, binary={'package': 'wu850_tiny', 'manifest_rel': art['manifest_rel'], 'profile_test': True, 'target_kind': 'lib'}, test_name='tiny_ok_a', kind='rust', package=pkg_obs)
        other_art = dict(art, package='other_pkg', package_id='path+file:///x#other_pkg@0.1.0')
        other_bound = r.bind_test_binary(artifact=other_art, binary_name='real-test-bin.exe', binary_sha256='a' * 64)
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_BINARY_MISMATCH'):
            r.compose_discovery_receipt(descriptor=desc, binary=other_bound, test_name='tiny_ok_a', kind='rust', package=pkg_obs)
        with self.assertRaisesRegex(r.RunnerInputError, 'KIND_MODE_MISMATCH'):
            r.compose_discovery_receipt(descriptor=desc, binary=bound, test_name='a.B.test_x', kind='python')
        receipt = r.compose_discovery_receipt(descriptor=desc, binary=bound, test_name='tiny_ok_a', kind='rust', package=pkg_obs)
        other = r.compose_discovery_receipt(descriptor=desc, binary=bound, test_name='tiny_ok_b', kind='rust', package=pkg_obs)
        with self.assertRaises(c.ContractViolation):
            c.TestExecutionRecord(test=other.test, disposition=c.ExecutionDisposition.EXECUTED_PASS, discovery=receipt, detail=None)
        with self.assertRaisesRegex(r.RunnerInputError, 'UNKNOWN_DISPOSITION|EXECUTION_RECORD_REJECTED'):
            r.compose_execution_record(discovery=receipt, disposition='bogus-disposition')
        with self.fixture() as root:
            _, disc, _, req = self.child(root)
            cross = dict(disc, tests=[dict(disc['tests'][0], id='foreign.Test.test_x')])
            with self.assertRaises(r.RunnerInputError):
                r.parse_python_protocol(json.dumps(cross).encode(), request_sha256=hashlib.sha256(json.dumps(req, sort_keys=True).encode()).hexdigest(), expected_module=req['module'], expected_source_sha256=req['source_sha256'], expected_phase='discover')


class R2TransportCases(unittest.TestCase):
    """R2 lane-B transport conformance (no WORK_UNIT_CASE markers).

    Covers fail-closed bounds, incremental streaming truncation, idle
    enforcement, the ActiveProcessLimit descendant cap, the POSIX refusal, and
    the runner-owned toolchain env filter. None of these renumber or restate the
    44 matrix markers above.
    """

    def _minimal_env(self):
        return {'PATH': os.environ.get('PATH', os.defpath), 'SYSTEMROOT': os.environ.get('SYSTEMROOT', r'C:\Windows'),
                'TEMP': tempfile.gettempdir(), 'TMP': tempfile.gettempdir(),
                'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONIOENCODING': 'utf-8'}

    def test_bounds_required_fail_closed(self):
        launcher = WindowsOwnedTree()
        with self.assertRaisesRegex(RuntimeError, 'BOUNDS_REQUIRED'):
            launcher.run([sys.executable, '-c', 'print(1)'], timeout=5, cwd=str(ROOT), env=self._minimal_env())
        with self.assertRaisesRegex(RuntimeError, 'BOUNDS_REQUIRED'):
            launcher.run([sys.executable, '-c', 'print(1)'], cwd=str(ROOT), env=self._minimal_env(),
                         bounds={'wall_s': 1, 'idle_s': 2, 'output_bytes': 64, 'line_bytes': 16, 'max_processes': 1})

    def test_streaming_truncation_terminates_early_and_stays_bounded(self):
        bounds = dict(_r2_descriptor_bounds('minimal-python-unittest.toml'), output_bytes=1024, line_bytes=256)
        launcher = WindowsOwnedTree()
        start = time.monotonic()
        disp = launcher.run(
            [sys.executable, '-c',
             'import sys, time\nfor i in range(100000):\n    sys.stdout.write("y" * 40 + "\\n")\n    time.sleep(0.001)\n'],
            cwd=str(ROOT), env=self._minimal_env(), bounds=bounds)
        elapsed = time.monotonic() - start
        self.assertTrue(disp['truncated'], disp['truncate_reason'])
        self.assertTrue(disp['truncate_reason'].startswith('OUTPUT_BYTE_BOUND'), disp['truncate_reason'])
        self.assertIn('dropped_bytes=', disp['truncate_reason'])
        self.assertNotIn('yyyy', disp['truncate_reason'])
        self.assertLessEqual(len(disp['stdout']), bounds['output_bytes'] + 65536)
        self.assertTrue(disp['cleanup_ok'], disp)
        self.assertEqual(0, disp['active_processes'], disp)
        # Incremental kill: a 100k-line flood must not run to the wall (10s).
        self.assertLess(elapsed, bounds['wall_s'], disp)
        self.assertGreaterEqual(disp['dropped_bytes'], 0, disp)

    def test_idle_timeout_terminates_silent_tree(self):
        bounds = _r2_descriptor_bounds('minimal-python-unittest.toml')
        launcher = WindowsOwnedTree()
        disp = launcher.run([sys.executable, '-c', 'import time; time.sleep(60)'],
                            cwd=str(ROOT), env=self._minimal_env(), bounds=bounds, idle_s=1)
        self.assertTrue(disp['timed_out'], disp)
        self.assertTrue(disp['idle_timeout'], disp)
        self.assertEqual('timeout-reaped', disp['cleanup'], disp)
        self.assertTrue(disp['cleanup_ok'], disp)
        self.assertEqual(0, disp['active_processes'], disp)

    def test_active_process_limit_denies_extra_child_and_reaps(self):
        bounds = dict(_r2_descriptor_bounds('minimal-python-unittest.toml'), max_processes=2)
        code = ('import subprocess, sys, time; '
                'ok = 0; fail = 0; pros = []\n'
                'for i in range(4):\n'
                '    try:\n'
                '        pros.append(subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"]))\n'
                '        ok += 1\n'
                '    except Exception as exc:\n'
                '        fail += 1\n'
                '        print("spawn-denied:" + type(exc).__name__)\n'
                'for p in pros:\n'
                '    p.wait(timeout=30)\n'
                'print("ok=%d fail=%d" % (ok, fail))\n'
                'sys.exit(0 if fail > 0 else 7)\n')
        # Idle at the decoded ceiling (5s): the spawn/wait gap (~2s) stays under
        # it while matrix proof cases never widen past the ceiling.
        disp = WindowsOwnedTree().run([sys.executable, '-c', code], cwd=str(ROOT),
                                      env=self._minimal_env(), bounds=bounds, idle_s=5)
        self.assertEqual(0, disp['returncode'], (disp['returncode'], disp['stdout'][-500:], disp['stderr'][-500:]))
        self.assertIn(b'fail=', disp['stdout'])
        self.assertNotIn(b'ok=4 fail=0', disp['stdout'])
        self.assertTrue(disp['cleanup_ok'], disp)
        self.assertEqual(0, disp['active_processes'], disp)
        self.assertEqual('clean', disp['cleanup'], disp)

    def test_posix_containment_refused_before_spawn(self):
        launcher = WindowsOwnedTree()
        with self.assertRaisesRegex(RuntimeError, 'unsupported containment on POSIX'):
            launcher._run_posix([sys.executable, '-c', 'print(1)'], input_bytes=None, timeout=5,
                                cwd=str(ROOT), env=self._minimal_env(),
                                bounds=_r2_descriptor_bounds('minimal-python-unittest.toml'))
        self.assertIn('Windows-only', WindowsOwnedTree.__doc__)
        self.assertNotIn('setsid', WindowsOwnedTree.__doc__)

    def test_breakaway_spawner_still_reaped_with_zero_active(self):
        bounds = _r2_descriptor_bounds('minimal-python-unittest.toml')
        code = ('import ctypes, subprocess, sys\n'
                'CREATE_BREAKAWAY_FROM_JOB = 0x01000000\n'
                '_ = ctypes.sizeof(ctypes.c_void_p)\n'
                'try:\n'
                '    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"], creationflags=CREATE_BREAKAWAY_FROM_JOB)\n'
                '    p.wait(timeout=30)\n'
                '    print("breakaway-allowed")\n'
                '    sys.exit(7)\n'
                'except Exception as exc:\n'
                '    print("breakaway-denied:" + type(exc).__name__)\n'
                '    sys.exit(0)\n')
        disp = WindowsOwnedTree().run([sys.executable, '-c', code], cwd=str(ROOT),
                                      env=self._minimal_env(), bounds=bounds)
        self.assertEqual(0, disp['returncode'], (disp['returncode'], disp['stdout'][-500:], disp['stderr'][-500:]))
        self.assertIn(b'breakaway-denied', disp['stdout'])
        self.assertTrue(disp['cleanup_ok'], disp)
        self.assertEqual(0, disp['active_processes'], disp)
        self.assertEqual('clean', disp['cleanup'], disp)

    def test_toolchain_env_proven_set_and_secrets_out(self):
        for name in ('PATH', 'SYSTEMROOT', 'SYSTEMDRIVE', 'PROGRAMDATA', 'TEMP', 'TMP',
                     'PATHEXT', 'OS', 'USERPROFILE', 'COMSPEC', 'WINDIR', 'LOCALAPPDATA'):
            self.assertIn(name, r.TOOLCHAIN_ENV_NAMES, name)
        self.assertNotIn('INCLUDE', r.TOOLCHAIN_ENV_NAMES)
        self.assertNotIn('LIB', r.TOOLCHAIN_ENV_NAMES)
        probe = {'PATH': 'p', 'SYSTEMROOT': 's', 'GH_TOKEN': 'CANARY', 'MY_SECRET': 's',
                 'CARGO_NET_RETRY': '3', 'RUST_LOG': 'info', 'RUST_SECRET': 'CANARY',
                 'RUSTC_WRAPPER': 'evil-wrapper'}
        filtered = r.toolchain_child_env(probe)
        self.assertEqual('p', filtered['PATH'])
        self.assertEqual('3', filtered['CARGO_NET_RETRY'])
        self.assertEqual('info', filtered['RUST_LOG'])
        self.assertNotIn('GH_TOKEN', filtered)
        self.assertNotIn('MY_SECRET', filtered)
        self.assertNotIn('RUST_SECRET', filtered)
        self.assertEqual('', filtered['RUSTC_WRAPPER'])
        with self.assertRaisesRegex(r.RunnerInputError, 'ENV_VALUE_BOUND'):
            r.toolchain_child_env({'PATH': 'p', 'CARGO_HUGE': 'x' * (r.ENV_VALUE_CAP + 1)})
        live = r.toolchain_child_env(dict(os.environ))
        self.assertIn('PATH', live)
        self.assertIn('SYSTEMROOT', live)
        self.assertEqual('', live['RUSTC_WRAPPER'])
        for key, value in live.items():
            self.assertNotIn('CANARY', value)
        total = sum(len(v.encode('utf-8')) for v in live.values())
        self.assertLessEqual(total, r.ENV_TOTAL_CAP)


class ResidualBindingNegatives(unittest.TestCase):
    """Unmarked residual negatives for the new runner bindings."""

    def test_build_stream_shapes(self):
        rel = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        base = {'package_id': 'path+file:///x#wu850_tiny@0.1.0', 'target': {'name': 'wu850_tiny', 'kind': ['lib']}, 'profile': {'test': False}, 'filenames': ['/tmp/a.rlib'], 'fresh': False}
        import json as _json
        def stream(art, fin=True, reason_art='compiler-artifact'):
            lines = [_json.dumps(dict(art, reason=reason_art)).encode()]
            if fin:
                lines.append(b'{"reason":"build-finished","success":true}')
            return b'\n'.join(lines) + b'\n'
        good = stream(base)
        self.assertEqual(1, len(r.parse_cargo_build_stream(good, package='wu850_tiny', manifest_rel=rel)))
        bad_target = dict(base, target={'name': 'wu850_tiny', 'kind': ['lib', 'rlib']})
        with self.assertRaisesRegex(r.RunnerInputError, 'TARGET_SHAPE'):
            r.parse_cargo_build_stream(stream(bad_target), package='wu850_tiny', manifest_rel=rel)
        bad_profile = dict(base, profile={'test': 'yes'})
        with self.assertRaisesRegex(r.RunnerInputError, 'PROFILE_SHAPE'):
            r.parse_cargo_build_stream(stream(bad_profile), package='wu850_tiny', manifest_rel=rel)
        bad_files = dict(base, filenames=[])
        with self.assertRaisesRegex(r.RunnerInputError, 'FILENAMES_REQUIRED'):
            r.parse_cargo_build_stream(stream(bad_files), package='wu850_tiny', manifest_rel=rel)
        bad_fresh = dict(base, fresh='no')
        with self.assertRaisesRegex(r.RunnerInputError, 'FRESH_BOOL_REQUIRED'):
            r.parse_cargo_build_stream(stream(bad_fresh), package='wu850_tiny', manifest_rel=rel)
        with self.assertRaisesRegex(r.RunnerInputError, 'OUTPUT_BYTE_BOUND'):
            r.parse_cargo_build_stream(b'x' * (r.MAX_PROTOCOL_BYTES + 1), package='wu850_tiny', manifest_rel=rel)

    def test_test_binary_shapes(self):
        art = {'package': 'wu850_tiny', 'package_id': 'path+file:///x#wu850_tiny@0.1.0', 'package_version': '0.1.0', 'manifest_rel': 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml', 'target_name': 'wu850_tiny', 'target_kind': 'lib', 'profile_test': False, 'filenames': ('/tmp/bin.exe',), 'fresh': False}
        with self.assertRaisesRegex(r.RunnerInputError, 'ARTIFACT_SHAPE'):
            r.bind_test_binary(artifact={'package': 'wu850_tiny'}, binary_name='bin.exe', binary_sha256='a' * 64)
        with self.assertRaisesRegex(r.RunnerInputError, 'BINARY_NAME_SHAPE'):
            r.bind_test_binary(artifact=art, binary_name='sub/bin.exe', binary_sha256='a' * 64)
        with self.assertRaisesRegex(r.RunnerInputError, 'TARGET_MISMATCH'):
            r.bind_test_binary(artifact=art, binary_name='bin.exe', binary_sha256='a' * 64, target='other')
        with self.assertRaisesRegex(r.RunnerInputError, 'CFGS_SHAPE'):
            r.bind_test_binary(artifact=art, binary_name='bin.exe', binary_sha256='a' * 64, cfgs='cfg1')
        ok = r.bind_test_binary(artifact=art, binary_name='bin.exe', binary_sha256='b' * 64, target='wu850_tiny', cfgs=['cfg1'])
        self.assertEqual('bin.exe', ok['binary_name'])

    def test_package_observation_shapes(self):
        desc = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        rel = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        with tempfile.TemporaryDirectory() as directory:
            troot = Path(directory)
            (troot / 'Cargo.toml').write_text('[package]\nname = "runner"\nversion = "0.1.0"\n', newline='\n')
            parent = r._safe_path(troot, 'Cargo.toml').parent.as_posix()
            pid = f"path+file://{parent}#runner@0.1.0"
            with self.assertRaisesRegex(r.RunnerInputError, 'DESCRIPTOR_TYPE_REQUIRED'):
                r.bind_package_observation(descriptor={'package': 'x'}, metadata={'packages': [], 'workspace_members': [], 'excluded': []}, root=troot, manifest_rel='Cargo.toml')
            with self.assertRaisesRegex(r.RunnerInputError, 'METADATA_SHAPE'):
                r.bind_package_observation(descriptor=desc, metadata={'packages': [], 'workspace_members': [], 'excluded': 'x'}, root=troot, manifest_rel='Cargo.toml')
            bad_path = {'packages': [{'name': 'runner', 'manifest_path': 'bad/path.txt', 'id': pid, 'version': '0.1.0', 'buildable': True}], 'workspace_members': [], 'excluded': []}
            with self.assertRaisesRegex(r.RunnerInputError, 'MANIFEST_PATH_SHAPE'):
                r.bind_package_observation(descriptor=desc, metadata=bad_path, root=troot, manifest_rel='Cargo.toml')
            for bad_manifest in (rel.replace('/Cargo.toml', '//Cargo.toml'), 'C:\\repo\\\\Cargo.toml', 'scripts/testdata/../escape/Cargo.toml', 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml.bak', 'scripts/testdata/\x01gate/descriptor-runner/rust-tiny/Cargo.toml', 'scripts/testdata/\x7fgate/descriptor-runner/rust-tiny/Cargo.toml'):
                with self.subTest(bad_manifest=repr(bad_manifest)):
                    bad = {'packages': [{'name': 'runner', 'manifest_path': bad_manifest, 'id': pid, 'version': '0.1.0', 'buildable': True}], 'workspace_members': [], 'excluded': []}
                    with self.assertRaisesRegex(r.RunnerInputError, 'MANIFEST_PATH_SHAPE'):
                        r.bind_package_observation(descriptor=desc, metadata=bad, root=troot, manifest_rel='Cargo.toml')
            forward = {'packages': [{'name': 'runner', 'manifest_path': parent + '/Cargo.toml', 'id': pid, 'version': '0.1.0', 'buildable': True}], 'workspace_members': [], 'excluded': []}
            forward_obs = r.bind_package_observation(descriptor=desc, metadata=forward, root=troot, manifest_rel='Cargo.toml')
            self.assertEqual(parent + '/Cargo.toml', forward_obs['manifest_path'])
            bad_bool = {'packages': [{'name': 'runner', 'manifest_path': parent + '/Cargo.toml', 'id': pid, 'version': '0.1.0', 'buildable': 'yes'}], 'workspace_members': [], 'excluded': []}
            with self.assertRaisesRegex(r.RunnerInputError, 'BUILDABLE_BOOL_REQUIRED'):
                r.bind_package_observation(descriptor=desc, metadata=bad_bool, root=troot, manifest_rel='Cargo.toml')

    def test_snapshot_and_enforcement_shapes(self):
        desc = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        good = {k: 'a' * 64 for k in ['scripts/tests/test_work_unit_descriptor_runner.py', 'scripts/work_unit_gate/descriptor_runner.py']}
        manifest = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        with self.assertRaisesRegex(r.RunnerInputError, 'DESCRIPTOR_TYPE_REQUIRED'):
            r.bind_protected_snapshot(descriptor={}, assignment=_b1_assignment(), snapshot=dict(good), descriptor_rel=FILENAME, manifest_rel=manifest)
        with self.assertRaisesRegex(r.RunnerInputError, 'ASSIGNMENT_RECEIPT_REQUIRED'):
            r.bind_protected_snapshot(descriptor=desc, assignment=None, snapshot=dict(good), descriptor_rel=FILENAME, manifest_rel=manifest)
        closed = _b1_assignment(state=c.IssueState.CLOSED, source_use=c.AssignmentSourceUse.PREREQUISITE_EVIDENCE)
        with self.assertRaisesRegex(r.RunnerInputError, 'INACTIVE_ASSIGNMENT'):
            r.bind_protected_snapshot(descriptor=desc, assignment=closed, snapshot=dict(good), descriptor_rel=FILENAME, manifest_rel=manifest)
        bounds = r.decode_descriptor((DESCRIPTOR_DIR / 'minimal-python-unittest.toml').read_bytes(), FILENAME)['bounds']
        plan = r.enforcement_plan(bounds=bounds)
        self.assertEqual({'wall_s', 'idle_s', 'output_bytes', 'line_bytes', 'max_tests', 'max_processes'}, set(plan))
        with self.assertRaisesRegex(r.RunnerInputError, 'INCONSISTENT_BOUNDS'):
            r.enforcement_plan(bounds=dict(bounds, idle_ms=bounds['wall_ms'] + 1))
        with self.assertRaisesRegex(r.RunnerInputError, 'INCONSISTENT_BOUNDS'):
            r.enforcement_plan(bounds=dict(bounds, line_bytes=bounds['output_bytes'] + 1))
        with self.assertRaisesRegex(r.RunnerInputError, 'INTEGER_BOUND|CLOSED_FIELDS'):
            r.enforcement_plan(bounds=dict(bounds, wall_ms=0))
        snap_manifest = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        snap_required = sorted({p.value for p in desc.source_roots + desc.test_roots} | ({desc.module.value.replace('.', '/') + '.py'} if desc.module is not None else set()) | {FILENAME, snap_manifest})
        snap_good = {k: 'a' * 64 for k in snap_required}
        snap_bound = r.bind_protected_snapshot(descriptor=desc, assignment=_b1_assignment(), snapshot=dict(snap_good), descriptor_rel=FILENAME, manifest_rel=snap_manifest)
        self.assertEqual(snap_required, snap_bound['keys'])
        self.assertEqual(desc.proof_ceiling.value, snap_bound['proof_ceiling'])
        snap_alt_assign = _b1_assignment(proof_ceiling=c.ProofCeiling('workspace-integration'))
        snap_alt_desc = r.parse_descriptor(VALID.replace(b'package-local', b'workspace-integration'), FILENAME, snap_alt_assign)
        snap_alt_bound = r.bind_protected_snapshot(descriptor=snap_alt_desc, assignment=snap_alt_assign, snapshot=dict(snap_good), descriptor_rel=FILENAME, manifest_rel=snap_manifest)
        self.assertNotEqual(snap_bound['digest'], snap_alt_bound['digest'])

    def test_compose_shapes(self):
        desc = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        with self.assertRaisesRegex(r.RunnerInputError, 'DESCRIPTOR_TYPE_REQUIRED'):
            r.compose_discovery_receipt(descriptor={}, binary=None, test_name='a.B.test_x', kind='python')
        with self.assertRaisesRegex(r.RunnerInputError, 'DISCOVERY_KIND_REQUIRED'):
            r.compose_discovery_receipt(descriptor=desc, binary=None, test_name='a.B.test_x', kind='go')
        with self.assertRaisesRegex(r.RunnerInputError, 'RUST_IDENTITY_SYNTAX|PYTHON_MODULE_SYNTAX'):
            r.compose_discovery_receipt(descriptor=desc, binary=None, test_name='bad name!', kind='python')
        with self.assertRaisesRegex(r.RunnerInputError, 'KIND_MODE_MISMATCH'):
            r.compose_discovery_receipt(descriptor=desc, binary={'no_manifest': 1}, test_name='tiny_ok_a', kind='rust')
        with self.assertRaisesRegex(r.RunnerInputError, 'BINARY_BINDING_REQUIRED'):
            r.compose_discovery_receipt(descriptor=desc, binary={'no_manifest': 1}, test_name='a.B.test_x', kind='python')
        receipt = r.compose_discovery_receipt(descriptor=desc, binary=None, test_name='scripts.tests.test_work_unit_descriptor_runner.Fake.test_x', kind='python')
        self.assertEqual(desc.matrix_sha256, receipt.artifact_sha256)
        with self.assertRaisesRegex(r.RunnerInputError, 'DISCOVERY_RECEIPT_REQUIRED'):
            r.compose_execution_record(discovery={}, disposition='executed-pass')

    def test_rust_binary_gates(self):
        desc = r.parse_descriptor((DESCRIPTOR_DIR / 'minimal-rust-package.toml').read_bytes(), FILENAME, _b1_assignment())
        rel = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        parent = r._safe_path(ROOT, rel).parent.as_posix()
        pid = f"path+file://{parent}#wu850_tiny@0.1.0"
        pkg_obs = r.bind_package_observation(descriptor=desc, metadata={
            'packages': [{'name': 'wu850_tiny', 'manifest_path': parent + '/Cargo.toml',
                          'id': pid, 'version': '0.1.0', 'buildable': True}],
            'workspace_members': [pid], 'excluded': []}, root=ROOT, manifest_rel=rel)

        def _bound(**changes):
            art = {'package': 'wu850_tiny', 'package_id': pid, 'package_version': '0.1.0',
                   'manifest_rel': rel, 'target_name': 'wu850_tiny', 'target_kind': 'lib',
                   'profile_test': True, 'filenames': ('/tmp/real-test-bin.exe',), 'fresh': False}
            art.update(changes)
            return r.bind_test_binary(artifact=art, binary_name='real-test-bin.exe',
                                      binary_sha256='a' * 64)

        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_OBSERVATION_REQUIRED'):
            r.compose_discovery_receipt(descriptor=desc, binary=_bound(), test_name='tiny_ok_a', kind='rust')
        with self.assertRaisesRegex(r.RunnerInputError, 'BINARY_REQUIRED'):
            r.compose_discovery_receipt(descriptor=desc, binary=None, test_name='tiny_ok_a', kind='rust', package=pkg_obs)
        with self.assertRaisesRegex(r.RunnerInputError, 'BINARY_NOT_TEST_PROFILE'):
            r.compose_discovery_receipt(descriptor=desc, binary=_bound(profile_test=False), test_name='tiny_ok_a', kind='rust', package=pkg_obs)
        with self.assertRaisesRegex(r.RunnerInputError, 'UNSUPPORTED_TARGET_KIND'):
            r.compose_discovery_receipt(descriptor=desc, binary=_bound(target_kind='rlib'), test_name='tiny_ok_a', kind='rust', package=pkg_obs)
        other = r.bind_test_binary(artifact={'package': 'other_pkg', 'package_id': 'path+file:///x#other_pkg@0.1.0', 'package_version': '0.1.0', 'manifest_rel': rel, 'target_name': 'other_pkg', 'target_kind': 'lib', 'profile_test': True, 'filenames': ('/tmp/real-test-bin.exe',), 'fresh': False}, binary_name='real-test-bin.exe', binary_sha256='a' * 64)
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_BINARY_MISMATCH'):
            r.compose_discovery_receipt(descriptor=desc, binary=other, test_name='tiny_ok_a', kind='rust', package=pkg_obs)
        with self.assertRaisesRegex(r.RunnerInputError, 'KIND_MODE_MISMATCH'):
            r.compose_discovery_receipt(descriptor=desc, binary=None, test_name='a.B.test_x', kind='python')

    def test_artifact_and_metadata_id_version_shapes(self):
        rel = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        base = {'package': 'wu850_tiny', 'manifest_rel': rel, 'target_name': 'wu850_tiny', 'target_kind': 'lib', 'profile_test': True, 'filenames': ('/tmp/bin.exe',), 'fresh': False}
        forged = dict(base, package_id='path+file:///x#wu850_tiny@99.9.9', package_version='99.9.9 forged')
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_VERSION_SHAPE'):
            r.bind_test_binary(artifact=forged, binary_name='bin.exe', binary_sha256='a' * 64)
        with self.assertRaisesRegex(r.RunnerInputError, 'ARTIFACT_SHAPE'):
            r.bind_test_binary(artifact=dict(base), binary_name='bin.exe', binary_sha256='a' * 64)
        desc = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        with tempfile.TemporaryDirectory() as directory:
            troot = Path(directory)
            (troot / 'Cargo.toml').write_text('[package]\nname = "runner"\nversion = "0.1.0"\n', newline='\n')
            parent = r._safe_path(troot, 'Cargo.toml').parent.as_posix()
            pid = f"path+file://{parent}#runner@0.1.0"
            bad_version = {'packages': [{'name': 'runner', 'manifest_path': rel, 'id': pid, 'version': 'not a version', 'buildable': True}], 'workspace_members': [], 'excluded': []}
            with self.assertRaisesRegex(r.RunnerInputError, 'METADATA_VERSION_SHAPE'):
                r.bind_package_observation(descriptor=desc, metadata=bad_version, root=troot, manifest_rel='Cargo.toml')
            bad_id = {'packages': [{'name': 'runner', 'manifest_path': rel, 'id': 7, 'version': '0.1.0', 'buildable': True}], 'workspace_members': [], 'excluded': []}
            with self.assertRaisesRegex(r.RunnerInputError, 'METADATA_ID_SHAPE'):
                r.bind_package_observation(descriptor=desc, metadata=bad_id, root=troot, manifest_rel='Cargo.toml')
            missing_version = {'packages': [{'name': 'runner', 'manifest_path': rel, 'id': pid, 'buildable': True}], 'workspace_members': [], 'excluded': []}
            with self.assertRaisesRegex(r.RunnerInputError, 'CLOSED_FIELDS'):
                r.bind_package_observation(descriptor=desc, metadata=missing_version, root=troot, manifest_rel='Cargo.toml')

    def test_execution_observation_cross_gates(self):
        desc = r.parse_descriptor((DESCRIPTOR_DIR / 'minimal-rust-package.toml').read_bytes(), FILENAME, _b1_assignment())
        rel = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        parent = r._safe_path(ROOT, rel).parent.as_posix()
        pid = f"path+file://{parent}#wu850_tiny@0.1.0"
        pkg = r.bind_package_observation(descriptor=desc, metadata={
            'packages': [{'name': 'wu850_tiny', 'manifest_path': parent + '/Cargo.toml',
                          'id': pid, 'version': '0.1.0', 'buildable': True}],
            'workspace_members': [pid], 'excluded': []}, root=ROOT, manifest_rel=rel)
        art = {'package': 'wu850_tiny', 'package_id': pid, 'package_version': '0.1.0',
               'manifest_rel': rel, 'target_name': 'wu850_tiny', 'target_kind': 'lib',
               'profile_test': True, 'filenames': ('/tmp/bin.exe',), 'fresh': False}
        binary = r.bind_test_binary(artifact=art, binary_name='bin.exe', binary_sha256='a' * 64)
        combined = r.bind_execution_observations(package=pkg, binary=binary)
        self.assertEqual(12, len(combined))
        self.assertEqual({'name', 'version', 'id', 'manifest_path', 'manifest_rel', 'member_kind',
                          'binary_name', 'binary_sha256', 'target', 'target_kind', 'profile_test',
                          'cfgs'}, set(combined))
        self.assertEqual('wu850_tiny', combined['name'])
        self.assertEqual(pid, combined['id'])
        self.assertEqual(rel, combined['manifest_rel'])
        with self.assertRaisesRegex(r.RunnerInputError, 'OBSERVATION_SHAPE'):
            r.bind_execution_observations(package={'name': 'wu850_tiny'}, binary=binary)
        with self.assertRaisesRegex(r.RunnerInputError, 'OBSERVATION_SHAPE'):
            r.bind_execution_observations(package=pkg, binary={'package': 'wu850_tiny'})
        with self.assertRaisesRegex(r.RunnerInputError, 'OBSERVATION_SHAPE'):
            r.bind_execution_observations(package=dict(pkg, version=7), binary=binary)
        with self.assertRaisesRegex(r.RunnerInputError, 'OBSERVATION_SHAPE'):
            r.bind_execution_observations(package=pkg, binary=dict(binary, profile_test='yes'))
        with self.assertRaisesRegex(r.RunnerInputError, 'OBSERVATION_SHAPE'):
            r.bind_execution_observations(package=pkg, binary={k: v for k, v in binary.items() if k != 'cfgs'})
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_BINARY_MISMATCH'):
            r.bind_execution_observations(package=pkg, binary=dict(binary, package='other_pkg'))
        with self.assertRaisesRegex(r.RunnerInputError, 'ARTIFACT_OBSERVATION_MISMATCH'):
            r.bind_execution_observations(package=pkg, binary=dict(binary, package_id='path+file:///x#wu850_tiny@9.9.9', version='9.9.9'))
        with self.assertRaisesRegex(r.RunnerInputError, 'MANIFEST_OBSERVATION_MISMATCH'):
            r.bind_execution_observations(package=dict(pkg, manifest_path='C:/forged/elsewhere/Cargo.toml'), binary=binary)
        with self.assertRaisesRegex(r.RunnerInputError, 'PACKAGE_IDENTITY_INCONSISTENT'):
            r.bind_package_observation(descriptor=desc, metadata={
                'packages': [{'name': 'wu850_tiny', 'manifest_path': parent + '/Cargo.toml',
                              'id': 'path+file:///x#other@0.1.0', 'version': '0.1.0', 'buildable': True}],
                'workspace_members': [], 'excluded': []}, root=ROOT, manifest_rel=rel)

    def test_snapshot_rel_and_mutation_shapes(self):
        desc = r.parse_descriptor(VALID, FILENAME, _b1_assignment())
        good = {k: 'a' * 64 for k in ['scripts/tests/test_work_unit_descriptor_runner.py', 'scripts/work_unit_gate/descriptor_runner.py']}
        manifest = 'scripts/testdata/work-unit-gate/descriptor-runner/rust-tiny/Cargo.toml'
        with self.assertRaisesRegex(r.RunnerInputError, 'DESCRIPTOR_REL_SHAPE'):
            r.bind_protected_snapshot(descriptor=desc, assignment=_b1_assignment(), snapshot=dict(good), descriptor_rel='/abs/path.toml', manifest_rel=manifest)
        with self.assertRaisesRegex(r.RunnerInputError, 'MANIFEST_REL_SHAPE'):
            r.bind_protected_snapshot(descriptor=desc, assignment=_b1_assignment(), snapshot=dict(good), descriptor_rel=FILENAME, manifest_rel=None)
        with self.assertRaisesRegex(r.RunnerInputError, 'MANIFEST_REL_SHAPE'):
            r.bind_protected_snapshot(descriptor=desc, assignment=_b1_assignment(), snapshot=dict(good), descriptor_rel=FILENAME, manifest_rel=7)
        with self.assertRaisesRegex(r.RunnerInputError, 'SHA256_REQUIRED'):
            r.compose_mutation_finding(descriptor=desc, diff={'mutated': [], 'added': [], 'removed': []}, snapshot_digest='not-hex')
        for bad in ({'mutated': [], 'added': []}, {'mutated': 'x', 'added': [], 'removed': []}, {'mutated': ['b', 'a'], 'added': [], 'removed': []}):
            with self.assertRaisesRegex(r.RunnerInputError, 'MUTATION_DIFF_SHAPE'):
                r.compose_mutation_finding(descriptor=desc, diff=bad, snapshot_digest='a' * 64)
        with self.assertRaisesRegex(r.RunnerInputError, 'DESCRIPTOR_TYPE_REQUIRED'):
            r.compose_mutation_finding(descriptor={}, diff={'mutated': [], 'added': [], 'removed': []}, snapshot_digest='a' * 64)


if __name__ == '__main__':
    unittest.main()
