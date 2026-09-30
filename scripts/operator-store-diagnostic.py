#!/usr/bin/env python3
"""Opt-in disposable Windows Store audit; never a governed product receipt.

Pinned official acquisition, existing #909 verifier, unchanged #994 tests.
No installed provider, policy override, ignored test, or live data is used.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.request

URL = 'https://github.com/surrealdb/surrealdb/releases/download/v3.1.4/surreal-v3.1.4.windows-amd64.exe'
DIGEST = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'
MAX_BYTES = 512 * 1024 * 1024
CEILING = 'OPERATOR_AUDIT_DIAGNOSTIC_ONLY_NOT_GOVERNED_ACCEPTANCE'
SMOKE = 'session_process_root_cleanup'


def common():
    spec = importlib.util.spec_from_file_location('operator_audit', Path(__file__).with_name('operator-audit-diagnostic.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def exact_pass(result, count):
    return (result.get('status') == 'EXPECTED_OUTCOME' and result.get('exit_code') == 0
            and result.get('test_counts') == {'passed': count, 'failed': 0, 'ignored': 0})



def input_identity(root):
    paths = ['docs/release/SURREALDB_WINDOWS_X64.lock.json', 'config/dependency-policy.toml',
             'scripts/integration/IntegrationHarness.Store.psm1', 'scripts/operator-store-diagnostic.py',
             'scripts/operator-audit-diagnostic.py', 'bins/eliot-kernel/tests/store_concurrency_product.rs']
    hashes = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths}
    catalog = json.loads((root / paths[0]).read_text(encoding='utf-8'))
    policy = tomllib.loads((root / paths[1]).read_text(encoding='utf-8'))['external_executables']['surrealdb']
    expected = dict(version='3.1.4', sha256=DIGEST)
    if any(record.get(key) != value for record in (catalog, policy) for key, value in expected.items()):
        raise RuntimeError('catalog/policy fixed provider pin mismatch; acquisition refused')
    if catalog.get('architecture') != 'windows-x64' or catalog.get('pe_machine') != '8664':
        raise RuntimeError('catalog provider platform mismatch; acquisition refused')
    return hashes


def acquire(destination):
    """Runs as a separately time-bounded child; never executes downloaded bytes."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix('.download')
    digest = hashlib.sha256()
    size = 0
    started = time.monotonic()
    request = urllib.request.Request(URL, headers={'User-Agent': 'eliot-operator-store-audit'})
    with urllib.request.urlopen(request, timeout=30) as response, temporary.open('xb') as target:
        if response.geturl().split(':', 1)[0] != 'https':
            raise RuntimeError('HTTPS release asset required')
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_BYTES or time.monotonic() - started > 180:
                raise RuntimeError('fixed asset download size/time bound exceeded')
            digest.update(chunk)
            target.write(chunk)
    actual = digest.hexdigest()
    print(json.dumps({'url': URL, 'bytes': size, 'sha256': actual, 'expected_sha256': DIGEST}), flush=True)
    if actual != DIGEST:
        raise RuntimeError('fixed provider digest mismatch; no execution permitted')
    temporary.replace(destination)


def ps_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def verifier(root, install):
    return "\n".join([
        "$ErrorActionPreference = 'Stop'",
        'Import-Module ' + ps_literal(root / 'scripts/integration/IntegrationHarness.Store.psm1') + ' -Force',
        '$acquire = New-StoreDefaultAcquisition -InstallRoot ' + ps_literal(install),
        "$result = & $acquire @{ artifact = 'surreal.exe' }",
        "$result | ConvertTo-Json -Depth 8",
        "if ($result.digest -cne '" + DIGEST + "' -or $result.version -cne '3.1.4') { throw 'fixed provider identity mismatch' }",
    ])


def cleanup_script(data):
    # Only executable images physically under this freshly allocated test root.
    # No process names/global service stop, no unrelated temp directories.
    return "\n".join([
        "$ErrorActionPreference = 'Stop'",
        '$root = ' + ps_literal(data),
        "$prefix = [IO.Path]::GetFullPath($root).TrimEnd('\\') + '\\'",
        '$owned = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })',
        'foreach ($p in $owned) { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop }',
        'Start-Sleep -Milliseconds 500',
        '$left = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })',
        "if ($left.Count -ne 0) { throw 'owned provider processes remain' }",
        '$removed = $false',
        'for ($i = 0; $i -lt 20; $i++) { try { if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }; $removed = $true; break } catch { Start-Sleep -Milliseconds 500 } }',
        "if (-not $removed -or (Test-Path -LiteralPath $root)) { throw 'disposable test root cleanup failed' }",
        "@{ status='OWNED_ROOT_REMOVED'; forcedProviderStops=$owned.Count } | ConvertTo-Json",
    ])


def plan(root, output, install):
    a = common()
    base = ['cargo', 'test', '--locked', '-p', 'eliot-kernel', '--test', 'store_concurrency_product']
    return [
        a.stage('rustc-identity', ['rustc', '-vV'], 5, contains='host: x86_64-pc-windows-msvc'),
        a.stage('cargo-identity', ['cargo', '--version'], 1),
        a.stage('metadata', ['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'], 2),
        a.stage('fixed-official-provider-download', [sys.executable, str(Path(__file__).resolve()), '--acquire', str(install / 'runtime/surreal.exe')], 4),
        a.stage('existing-909-provider-verifier', ['pwsh', '-NoProfile', '-File', str(output / 'verify-provider.ps1')], 1),
        a.stage('store-target-compile-test-profile', base + ['--no-run'], 20),
        a.stage('store-smoke-cleanup', base + [SMOKE, '--', '--exact', '--nocapture', '--test-threads=1'], 5, tests=True, contains='SCONC-994 case=18 cleanup ok'),
        # First real smoke took 97.66s: allow the 16-case target up to 30min,
        # still bounded by the unchanged 42min global ceiling and cleanup reserve.
        a.stage('store-sixteen-cases', base + ['--no-fail-fast', '--', '--nocapture', '--test-threads=1'], 30, tests=True),
    ]



def run_cleanup(spec, output, root, seconds):
    """Cleanup remains attempted even when build disk-floor checks stopped work."""
    stdout = output / 'owned-root-cleanup.stdout.log'
    stderr = output / 'owned-root-cleanup.stderr.log'
    started = time.monotonic()
    result = dict(spec, status='FAILED', exit_code=None, stdout=str(stdout), stderr=str(stderr))
    try:
        with stdout.open('wb') as out, stderr.open('wb') as err:
            proc = subprocess.run(spec['command'], cwd=root, stdin=subprocess.DEVNULL,
                                  stdout=out, stderr=err, timeout=max(1, min(42, seconds)))
        result['exit_code'] = proc.returncode
        if proc.returncode == 0 and 'OWNED_ROOT_REMOVED' in stdout.read_text(encoding='utf-8', errors='replace'):
            detail = json.loads(stdout.read_text(encoding='utf-8-sig'))
            result['forced_provider_stops'] = detail['forcedProviderStops']
            result['cleanup_kind'] = 'SUPERVISOR_CONTAINMENT' if detail['forcedProviderStops'] else 'NO_RESIDUAL_PROVIDER_FOUND'
            result['fixture_cleanup_proven'] = False
            result['status'] = 'EXPECTED_OUTCOME'
    except subprocess.TimeoutExpired:
        result.update(status='TIMED_OUT', reason='cleanup deadline; runner teardown required')
    except (OSError, ValueError, KeyError) as error:
        result['reason'] = str(error)
    result['elapsed_seconds'] = round(time.monotonic() - started, 3)
    for key, path in [('stdout_sha256', stdout), ('stderr_sha256', stderr)]:
        if path.exists():
            result[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    print('DIAGNOSTIC_RESULT ' + json.dumps(result), flush=True)
    return result


def self_test():
    import unittest
    from unittest.mock import patch
    import io
    class Tests(unittest.TestCase):
        def test_exact_gate(self):
            good = dict(status='EXPECTED_OUTCOME', exit_code=0, test_counts=dict(passed=1, failed=0, ignored=0))
            self.assertTrue(exact_pass(good, 1))
            for count in (0, 2, 16):
                self.assertFalse(exact_pass(good, count))
            for field, value in [('status', 'FAILED'), ('exit_code', 101), ('test_counts', dict(passed=1, failed=1, ignored=0)), ('test_counts', dict(passed=1, failed=0, ignored=1))]:
                self.assertFalse(exact_pass(dict(good, **{field: value}), 1))
        def test_plan(self):
            rows = plan(Path('/repo'), Path('/evidence'), Path('/install'))
            self.assertEqual(len(rows), 8)
            self.assertEqual(rows[0]['timeout_seconds'], 300)
            self.assertIn('--no-run', rows[5]['command'])
            self.assertIn('--exact', rows[6]['command'])
            self.assertIn(SMOKE, rows[6]['command'])
            self.assertNotIn(SMOKE, rows[7]['command'])
            self.assertEqual(rows[7]['timeout_seconds'], 30 * 60)
            self.assertTrue(all('--ignored' not in x['command'] for x in rows))
        def test_catalog_pin_gate(self):
            root = Path(__file__).resolve().parents[1]
            self.assertEqual(len(input_identity(root)), 6)
            with patch.dict(globals(), DIGEST='0'*64):
                with self.assertRaisesRegex(RuntimeError, 'pin mismatch'):
                    input_identity(root)
        def test_pin_and_verifier(self):
            self.assertEqual(len(DIGEST), 64)
            self.assertIn('/v3.1.4/', URL)
            self.assertIn('New-StoreDefaultAcquisition', verifier(Path('/repo'), Path('/install')))
            self.assertNotIn('Invoke-StoreStart', verifier(Path('/repo'), Path('/install')))
        def test_download_digest_gate(self):
            class Response(io.BytesIO):
                def geturl(self):
                    return URL
            with tempfile.TemporaryDirectory() as directory:
                destination = Path(directory) / 'runtime/surreal.exe'
                with patch('urllib.request.urlopen', return_value=Response(b'wrong provider')):
                    with self.assertRaisesRegex(RuntimeError, 'digest mismatch'):
                        acquire(destination)
                self.assertFalse(destination.exists())
        def test_download_size_gate(self):
            class Response(io.BytesIO):
                def geturl(self):
                    return URL
            with tempfile.TemporaryDirectory() as directory:
                destination = Path(directory) / 'surreal.exe'
                with patch('urllib.request.urlopen', return_value=Response(b'large')), patch.dict(globals(), MAX_BYTES=1):
                    with self.assertRaisesRegex(RuntimeError, 'size/time bound'):
                        acquire(destination)
                self.assertFalse(destination.exists())
        def test_path_quoting(self):
            self.assertEqual(ps_literal("a'b"), "'a''b'")
            self.assertIn('ExecutablePath.StartsWith', cleanup_script(Path('/only-owned')))
    return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests)).wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--plan-only', action='store_true')
    parser.add_argument('--acquire', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.acquire:
        input_identity(Path(__file__).resolve().parents[1])
        acquire(args.acquire)
        return 0
    if args.output is None:
        parser.error('--output is required')
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    a = common()
    hashes = input_identity(root)
    sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    if not args.plan_only and (os.name != 'nt' or os.environ.get('CARGO_FEATURE_PURE')):
        raise SystemExit('Native Windows without CARGO_FEATURE_PURE is required')
    data = (output.parent / 'store-plan-disposable') if args.plan_only else Path(tempfile.mkdtemp(prefix='eliot-store-audit-'))
    install = data / 'provider-stage'
    rows = plan(root, output, install)
    record = dict(ceiling=CEILING, source_sha=sha, input_sha256=hashes, profile='native Windows dev/test unoptimized debug=0',
                  provider=dict(version='3.1.4', url=URL, sha256=DIGEST, max_bytes=MAX_BYTES),
                  global_seconds=42*60, unique_target_tests=16, smoke_repeats_one_target_test=True,
                  full_target_condition='All prerequisites pass; smoke exactly 1 passed, 0 failed, 0 ignored plus explicit cleanup marker',
                  stages=rows, cleanup=dict(command=['pwsh', '-NoProfile', '-File', str(output / 'cleanup-owned.ps1')], timeout_seconds=42, scope='fresh disposable root and processes whose executable path is under it', failure='retained nonzero; disposable runner teardown remains final containment'))
    a.write_json(output / 'plan.json', record)
    (output / 'verify-provider.ps1').write_text(verifier(root, install), encoding='utf-8')
    if args.plan_only:
        return 0
    os.environ.update(CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TERM_COLOR='never')
    os.environ.update(TEMP=str(data), TMP=str(data), ELIOT_TEST_SURREAL_EXE=str(install / 'runtime/surreal.exe'))
    (output / 'cleanup-owned.ps1').write_text(cleanup_script(data), encoding='utf-8')
    deadline = time.monotonic() + 42*60
    results = []
    allowed = True
    try:
        for row in rows:
            if not allowed:
                result = dict(row, status='SKIPPED', exit_code=None, reason='prior prerequisite or exact test-count gate failed')
            else:
                result = a.execute(row, output, root, deadline-time.monotonic()-45)
                if row['name'] in ('store-smoke-cleanup', 'store-sixteen-cases'):
                    expected = 1 if row['name'] == 'store-smoke-cleanup' else 16
                    result['count_gate'] = dict(expected_passed=expected, met=exact_pass(result, expected))
                    if result['status'] == 'EXPECTED_OUTCOME' and not exact_pass(result, expected):
                        result.update(status='FAILED', reason=f'exact {expected}-pass, zero-fail/ignored test gate not met')
                allowed = result['status'] == 'EXPECTED_OUTCOME'
            results.append(result)
            a.write_json(output / 'results.json', dict(record, disposable_data_root=str(data), results=results))
    finally:
        cleanup = a.stage('owned-root-cleanup', ['pwsh', '-NoProfile', '-File', str(output / 'cleanup-owned.ps1')], .7, contains='OWNED_ROOT_REMOVED')
        results.append(run_cleanup(cleanup, output, root, deadline-time.monotonic()))
        a.write_json(output / 'results.json', dict(record, disposable_data_root=str(data), results=results))
    return 0 if all(x['status'] == 'EXPECTED_OUTCOME' for x in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
