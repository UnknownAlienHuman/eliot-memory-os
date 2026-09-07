"""#849: real source-adapter paths with finite HTTP/file/clock fixtures.

No live token/network is used. The trusted capture digest is a separately
frozen fixture constant, not taken from the worker-controlled snapshot.
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scripts.work_unit_gate import assignment_source as s
from scripts.work_unit_gate import contracts as c

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'scripts/testdata/work-unit-gate/assignment-source'
LIVE = json.loads((FIXTURES / 'valid-issue.json').read_text())
OFFLINE = (FIXTURES / 'valid-offline.json').read_bytes()
CAPTURE_SHA = '0fa6033d6cd8db573ec621bd27c7f966c56d69eda8803bcbc1ec9c05065433a8'
BODY = LIVE['body']
ISSUE = c.IssueIdentity(c.RepositoryIdentity('ExampleOwner', 'example-repo'), 849)
REQUEST = s.SourceRequest(ISSUE, c.WorkUnitIdentity('A-1'), c.AssignmentSourceUse.ACTIVE_ASSIGNMENT)
LIVE_MODE = c.SourceAuthority.LIVE_GITHUB
OFFLINE_MODE = c.SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT


def response(*, payload=None, body=None, status=200, url=None, headers=None):
    return s.HTTPResult(status, url or REQUEST.endpoint,
        headers if headers is not None else (('content-type', 'application/json; charset=utf-8'), ('etag', 'W/"fixture"')),
        body if body is not None else json.dumps(payload or LIVE).encode('utf-8'))


def acquire(payload=None, *, observed=None, request=REQUEST, limits=s.SourceLimits(), **options):
    observed = observed or response(payload=payload)
    return s.AssignmentSource(request, limits=limits, _transport=lambda *_: observed, **options).read(LIVE_MODE)


def snapshot(**updates):
    value = json.loads(OFFLINE)
    value['payload'].update(updates)
    value['snapshot_sha256'] = c.canonical_sha256({'schema': value['schema'], 'payload': value['payload']})
    return json.dumps(value).encode(), value['snapshot_sha256']


class SourceTests(unittest.TestCase):
    def reject(self, code, operation, *args, **kwargs):
        with self.assertRaises(s.SourceError) as result:
            operation(*args, **kwargs)
        self.assertIs(result.exception.code, code)
        return result.exception

    def parse(self, body, limits=s.SourceLimits()):
        return s.parse_matrix(body, ISSUE, limits)

    def read_offline(self, raw=OFFLINE, *, expected=CAPTURE_SHA, now=1200, request=REQUEST,
                     producer='controller', receipt='e'*64, policy='f'*64, max_age=600):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.json'
            path.write_bytes(raw)
            permit = s.TrustedOfflineCapture(request, path, expected, c.WorkUnitIdentity(producer), receipt, policy, max_age)
            source = s.AssignmentSource(request, offline=permit, clock=lambda: now,
                                        _transport=lambda *_: self.fail('offline made a network request'))
            result = source.read(OFFLINE_MODE)
            self.assertEqual(raw, path.read_bytes())
            self.assertEqual(['capture.json'], [item.name for item in Path(directory).iterdir()])
            return result

    # WORK_UNIT_CASE: 849/1
    def test_valid_live_active_assignment(self):
        result = acquire()
        self.assertIs(type(result.receipt), c.AssignmentSourceReceipt)
        self.assertEqual(REQUEST.issue, result.receipt.issue)
        self.assertEqual([1, 2], [item.identity.number for item in result.matrix.cases])
        self.assertEqual(2, result.receipt.matrix_cases)
        self.assertIs(result.receipt.authority, LIVE_MODE)
        self.assertEqual('assignment-source-only', result.receipt.proof_ceiling.value)
        for case in result.matrix.cases:
            self.assertEqual(case.text.encode(), BODY.encode()[case.start_byte:case.end_byte])

    # WORK_UNIT_CASE: 849/2
    def test_missing_heading(self):
        self.reject(s.SourceProblem.MATRIX_MISSING, self.parse, BODY.replace('## Required test matrix', '## Examples'))

    # WORK_UNIT_CASE: 849/3
    def test_duplicate_heading_even_after_section_end(self):
        self.reject(s.SourceProblem.MATRIX_MULTIPLE, self.parse, BODY + '\n## Required test matrix\n1. extra\n')

    # WORK_UNIT_CASE: 849/4
    def test_wrong_heading_level(self):
        for heading in ('# Required test matrix', '### Required test matrix'):
            with self.subTest(heading=heading):
                self.reject(s.SourceProblem.MATRIX_HEADING, self.parse, BODY.replace('## Required test matrix', heading))

    # WORK_UNIT_CASE: 849/5
    def test_numbering_starts_at_zero(self):
        self.reject(s.SourceProblem.MATRIX_NUMBERING, self.parse, BODY.replace('1. Accept', '0. Accept'))

    # WORK_UNIT_CASE: 849/6
    def test_numbering_starts_at_two(self):
        self.reject(s.SourceProblem.MATRIX_NUMBERING, self.parse, BODY.replace('1. Accept', '2. Accept'))

    # WORK_UNIT_CASE: 849/7
    def test_missing_middle_case(self):
        self.reject(s.SourceProblem.MATRIX_NUMBERING, self.parse, BODY.replace('2. Reject', '3. Reject'))

    # WORK_UNIT_CASE: 849/8
    def test_duplicate_case(self):
        self.reject(s.SourceProblem.MATRIX_NUMBERING, self.parse, BODY.replace('2. Reject', '1. Reject'))

    # WORK_UNIT_CASE: 849/9
    def test_out_of_order_case(self):
        changed = BODY.replace('2. Reject a changed identity.', '3. Third.\n2. Second.')
        self.reject(s.SourceProblem.MATRIX_NUMBERING, self.parse, changed)

    # WORK_UNIT_CASE: 849/10
    def test_fenced_examples_cannot_supply_cases_or_heading(self):
        for fence in ('```', '~~~~'):
            with self.subTest(fence=fence):
                extra = f'{fence}\n## Required test matrix\n0. fake\n999. fake\n{fence}\n'
                result = self.parse(extra + BODY.replace('2. Reject', extra + '2. Reject'))
                self.assertEqual([1, 2], [item.identity.number for item in result.cases])

    # WORK_UNIT_CASE: 849/11
    def test_indented_code_is_not_numbered_case(self):
        result = self.parse(BODY.replace('2. Reject', '    777. example\n\t888. example\n2. Reject'))
        self.assertEqual(2, len(result.cases))
        self.assertIn('777. example', result.cases[0].text)

    # WORK_UNIT_CASE: 849/12
    def test_quoted_numbering_and_heading_are_ignored(self):
        result = self.parse('> ## Required test matrix\n> 99. quoted\n' + BODY.replace('2. Reject', '> 0. quoted\n2. Reject'))
        self.assertEqual(2, len(result.cases))

    # WORK_UNIT_CASE: 849/13
    def test_nested_numbered_example_does_not_reset_sequence(self):
        for indent in (' ', '  ', '   ', '    '):
            with self.subTest(indent=indent):
                result = self.parse(BODY.replace('2. Reject', indent + '1. nested\n2. Reject'))
                self.assertEqual(2, len(result.cases))

    # WORK_UNIT_CASE: 849/14
    def test_major_heading_ends_matrix_and_h3_does_not_reset_it(self):
        result = self.parse(BODY.replace('2. Reject', '### Group B\n2. Reject') + '99. outside matrix\n')
        self.assertEqual(2, len(result.cases))
        self.assertNotIn('Group B', result.cases[0].text)
        self.assertNotIn('outside', result.cases[1].text)
        self.assertEqual(2, len(self.parse(BODY.replace('## Verification', '# Verification')).cases))

    # WORK_UNIT_CASE: 849/15
    def test_exact_body_and_matrix_hashes(self):
        first, second = self.parse(BODY), self.parse(BODY)
        self.assertEqual(first, second)
        self.assertEqual('fc271d58d317415841a11d1b3e6d8b1f421f85f519dcdf8d8618c21ca74886e3', first.body_sha256)
        self.assertEqual('e67377c83429511ae03dd1dcf8f73a2252ab1ffa19e726e295c02c10946e9b10', first.matrix_sha256)
        prefix_changed = self.parse('A new intro.\n' + BODY)
        self.assertNotEqual(first.body_sha256, prefix_changed.body_sha256)
        self.assertEqual(first.matrix_sha256, prefix_changed.matrix_sha256)
        self.assertNotEqual(first.matrix_sha256, self.parse(BODY.replace('changed identity.', 'different identity.')).matrix_sha256)

    # WORK_UNIT_CASE: 849/16
    def test_a1_cannot_match_a10(self):
        self.reject(s.SourceProblem.IDENTITY, acquire, LIVE | {'title': '[A-10] Not A-1'})

    # WORK_UNIT_CASE: 849/17
    def test_title_and_exact_unit_token_grammar(self):
        for title in ('[A-1] Valid title', '[A-1] Кириллица и café'):
            self.assertEqual(title, acquire(LIVE | {'title': title}).receipt.title)
        for title in ('A-1 bare title', '[A-1x] Other unit', '[A-1]No separator', '[A-1] Bad\nline'):
            self.reject(s.SourceProblem.IDENTITY, acquire, LIVE | {'title': title})

    # WORK_UNIT_CASE: 849/18
    def test_pr_object_rejected_even_with_matching_number(self):
        self.reject(s.SourceProblem.PR_OBJECT, acquire, LIVE | {'pull_request': {}})
        self.reject(s.SourceProblem.PR_OBJECT, acquire, LIVE | {'pull_request': None})

    # WORK_UNIT_CASE: 849/19
    def test_closed_owner_cannot_authorize_active_assignment(self):
        self.reject(s.SourceProblem.CLOSED, acquire, LIVE | {'state': 'closed'})

    # WORK_UNIT_CASE: 849/20
    def test_explicit_supersession_cannot_authorize_active_work(self):
        for changes in ({'labels': [{'name': 'superseded'}]}, {'title': '[A-1] SUPERSEDED by #850'},
                        {'body': 'Superseded by #850\n' + BODY}):
            self.reject(s.SourceProblem.SUPERSEDED, acquire, LIVE | changes)
        self.assertIs(acquire(LIVE | {'body': '```\nSuperseded by #850\n```\n' + BODY}).receipt.state, c.IssueState.OPEN)

    # WORK_UNIT_CASE: 849/21
    def test_malformed_json_media_and_required_schema(self):
        for raw in (b'{', b'[]', b'null', b'{"x":NaN}', b'{"number":849,"number":850}', b'{"x":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(s.SourceError):
                acquire(observed=response(body=raw))
        self.reject(s.SourceProblem.MEDIA, acquire, observed=response(headers=(('content-type', 'text/html'),)))
        for field in ('number', 'title', 'body', 'state', 'labels', 'updated_at'):
            broken = dict(LIVE); del broken[field]
            with self.subTest(field=field), self.assertRaises(s.SourceError):
                acquire(broken)
        self.reject(s.SourceProblem.SCHEMA, acquire, LIVE | {'number': True})

    # WORK_UNIT_CASE: 849/22
    def test_response_body_depth_line_and_case_limits(self):
        self.reject(s.SourceProblem.RESPONSE_LIMIT, acquire,
                    observed=response(body=b' ' * 1_048_577))
        limits = dataclasses.replace(s.SourceLimits(), body_bytes=128, line_bytes=128, case_bytes=128)
        self.reject(s.SourceProblem.BODY_LIMIT, acquire, limits=limits)
        self.reject(s.SourceProblem.STRUCTURE_LIMIT, acquire, LIVE | {'extra': [[[[1]]]]},
                    limits=dataclasses.replace(s.SourceLimits(), json_depth=3))
        for key, value in (('cases', 1), ('lines', 2), ('line_bytes', 20), ('json_items', 2), ('case_bytes', 10)):
            with self.subTest(key=key):
                self.reject(s.SourceProblem.STRUCTURE_LIMIT, acquire, limits=dataclasses.replace(s.SourceLimits(), **{key: value}))

    # WORK_UNIT_CASE: 849/23
    def test_timeout_unavailable_rate_limit_and_auth_remain_distinct(self):
        for status, headers, code in (
            (401, (), s.SourceProblem.AUTH), (403, (), s.SourceProblem.FORBIDDEN),
            (403, (('x-ratelimit-remaining', '0'),), s.SourceProblem.RATE_LIMIT),
            (403, (('retry-after', '60'),), s.SourceProblem.RATE_LIMIT),
            (429, (), s.SourceProblem.RATE_LIMIT), (503, (), s.SourceProblem.UNAVAILABLE),
            (404, (), s.SourceProblem.NOT_FOUND)):
            self.reject(code, acquire, observed=response(status=status, headers=headers))
        for error, code in ((TimeoutError('secret'), s.SourceProblem.TIMEOUT), (OSError('secret'), s.SourceProblem.UNAVAILABLE)):
            def failed(*_, error=error):
                raise error
            self.reject(code, s.AssignmentSource(REQUEST, _transport=failed).read, LIVE_MODE)

    # WORK_UNIT_CASE: 849/24
    def test_redirect_is_rejected_without_following(self):
        calls = []
        def redirected(request, *_):
            calls.append(request.endpoint)
            return response(status=302, headers=(('location', 'https://foreign.invalid/token-canary'),))
        self.reject(s.SourceProblem.REDIRECT, s.AssignmentSource(REQUEST, _transport=redirected).read, LIVE_MODE)
        self.assertEqual([REQUEST.endpoint], calls)

    # WORK_UNIT_CASE: 849/25
    def test_foreign_origin_repository_or_path_is_rejected(self):
        for url in ('http://api.github.com/repos/ExampleOwner/example-repo/issues/849', REQUEST.endpoint + '/comments',
                    REQUEST.endpoint.replace('api.github.com', 'api.github.com.evil.invalid')):
            self.reject(s.SourceProblem.ORIGIN, acquire, observed=response(url=url))
        for field, value in (('repository_url', 'https://api.github.com/repos/Other/repo'),
                             ('url', REQUEST.endpoint + '?extra=1'), ('html_url', 'https://github.com/Other/repo/issues/849')):
            self.reject(s.SourceProblem.ORIGIN, acquire, LIVE | {field: value})

    # WORK_UNIT_CASE: 849/26
    def test_token_body_and_transport_errors_never_escape_diagnostics(self):
        observed = []
        def broken(_request, _limits, token):
            observed.append(token)
            raise RuntimeError('token-secret-canary and body-secret-canary')
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'token-secret-canary'}):
            error = self.reject(s.SourceProblem.INTERNAL,
                s.AssignmentSource(REQUEST, token_env='GITHUB_TOKEN', _transport=broken).read, LIVE_MODE)
        self.assertEqual(['token-secret-canary'], observed)
        self.assertNotIn('canary', str(error)); self.assertNotIn('canary', repr(error))
        document = acquire(LIVE | {'body': BODY.replace('current identity.', 'body-secret-canary.')})
        self.assertNotIn('canary', repr(document)); self.assertNotIn('canary', repr(document.matrix))

    # WORK_UNIT_CASE: 849/27
    def test_explicit_controller_admitted_offline_file(self):
        document = self.read_offline()
        self.assertIs(document.receipt.authority, OFFLINE_MODE)
        self.assertEqual(BODY, document.body)
        self.assertEqual(CAPTURE_SHA, document.receipt.offline_capture.expected_snapshot_sha256)
        self.assertIsNone(document.receipt.live_etag)
        self.assertEqual('W/"capture"', document.captured_etag)

    # WORK_UNIT_CASE: 849/28
    def test_offline_repository_issue_unit_use_and_relation_mismatch(self):
        for key, value in (('repository', 'Other/repo'), ('number', 850), ('unit', 'A-10'),
                           ('source_use', 'prerequisite-evidence'),
                           ('relation', {'source': 849, 'role': 'blocked-by', 'target': 850})):
            raw, trusted = snapshot(**{key: value})
            self.reject(s.SourceProblem.IDENTITY, self.read_offline, raw, expected=trusted)

    # WORK_UNIT_CASE: 849/29
    def test_offline_body_matrix_and_snapshot_hash_mismatch(self):
        for key in ('body_sha256', 'matrix_sha256'):
            raw, trusted = snapshot(**{key: 'a'*64})
            self.reject(s.SourceProblem.CAPTURE_DIGEST, self.read_offline, raw, expected=trusted)
        self.reject(s.SourceProblem.CAPTURE_DIGEST, self.read_offline, expected='a'*64)
        tampered = json.loads(OFFLINE); tampered['payload']['body'] += 'tampered'
        self.reject(s.SourceProblem.CAPTURE_DIGEST, self.read_offline, json.dumps(tampered).encode())

    # WORK_UNIT_CASE: 849/30
    def test_stale_expired_invalidated_and_incomplete_capture(self):
        for now in (999, 1600, 2000):
            self.reject(s.SourceProblem.CAPTURE_STALE, self.read_offline, now=now)
        for updates in ({'invalidated': True}, {'complete': False}, {'complete': 1}, {'expires_at': 1000},
                        {'expires_at': 1601}):
            raw, trusted = snapshot(**updates)
            self.reject(s.SourceProblem.CAPTURE_STALE, self.read_offline, raw, expected=trusted)

    # WORK_UNIT_CASE: 849/31
    def test_modes_never_fall_back_or_cross_read_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'offline.json'; path.write_bytes(OFFLINE)
            permit = s.TrustedOfflineCapture(REQUEST, path, CAPTURE_SHA, c.WorkUnitIdentity('controller'), 'e'*64, 'f'*64, 600)
            def failed(*_): raise OSError('unavailable')
            source = s.AssignmentSource(REQUEST, offline=permit, _transport=failed,
                _reader=lambda *_: self.fail('live mode accessed fallback'))
            self.reject(s.SourceProblem.UNAVAILABLE, source.read, LIVE_MODE)
        self.read_offline()  # Its transport raises if ever called.
        self.reject(s.SourceProblem.UNTRUSTED_CAPTURE, s.AssignmentSource(REQUEST).read, OFFLINE_MODE)
        self.reject(s.SourceProblem.CONFIGURATION, s.AssignmentSource(REQUEST).read, 'live-github')

    # WORK_UNIT_CASE: 849/32
    def test_fixed_origin_get_only_no_mutation_cache_or_endpoint_override(self):
        calls = []
        class Socket:
            def settimeout(self, timeout): calls.append(('timeout', timeout))
        class Reply:
            status = 200
            def __init__(self): self.raw = response().body
            def getheaders(self): return [('content-type', 'application/json'), ('content-length', str(len(self.raw)))]
            def read1(self, size): chunk, self.raw = self.raw[:size], self.raw[size:]; return chunk
        class Connection:
            def __init__(self, host, **kw): calls.append(('host', host)); self.sock = Socket()
            def connect(self): calls.append(('connect',))
            def request(self, method, path, *, headers): calls.append(('request', method, path, dict(headers)))
            def getresponse(self): return Reply()
            def close(self): calls.append(('close',))
        with patch.object(s.http.client, 'HTTPSConnection', Connection):
            observed = s._https_get(REQUEST, s.SourceLimits(), 'read-only-fixture')
        self.assertEqual(REQUEST.endpoint, observed.url)
        request = next(call for call in calls if call[0] == 'request')
        self.assertEqual(('GET', '/repos/ExampleOwner/example-repo/issues/849'), request[1:3])
        self.assertNotIn('If-None-Match', request[3])
        self.assertIn(('host', 'api.github.com'), calls)
        self.assertEqual(('close',), calls[-1])
        self.reject(s.SourceProblem.NOT_MODIFIED, acquire, observed=response(status=304))
        with self.assertRaises(TypeError): s.AssignmentSource(REQUEST, url='https://foreign.invalid')

    # WORK_UNIT_CASE: 849/33
    def test_closed_prerequisite_retains_state_and_lower_ceiling(self):
        relation = c.AssignmentRelation(ISSUE, c.RelationRole.BLOCKED_BY, c.IssueIdentity(ISSUE.repository, 857))
        request = dataclasses.replace(REQUEST, source_use=c.AssignmentSourceUse.PREREQUISITE_EVIDENCE, relation=relation)
        document = acquire(LIVE | {'state': 'closed'}, request=request)
        self.assertIs(document.receipt.state, c.IssueState.CLOSED)
        self.assertEqual(relation, document.relation)
        self.assertEqual('historical-assignment-source-only', document.receipt.proof_ceiling.value)
        self.assertFalse(hasattr(document.receipt, 'accepted_commit'))
        self.reject(s.SourceProblem.CONFIGURATION, s.SourceRequest, ISSUE, REQUEST.unit, c.RelationRole.BLOCKED_BY)
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(document.receipt, source_use=c.AssignmentSourceUse.ACTIVE_ASSIGNMENT)

    # WORK_UNIT_CASE: 849/34
    def test_worker_self_hash_or_producer_cannot_create_controller_trust(self):
        raw, self_hash = snapshot(body=BODY.replace('current identity', 'worker-chosen identity'))
        self.reject(s.SourceProblem.CAPTURE_DIGEST, self.read_offline, raw)
        self.assertNotEqual(CAPTURE_SHA, self_hash)
        for field in ('producer', 'capture_receipt_sha256', 'freshness_policy_sha256'):
            value = 'untrusted-worker' if field == 'producer' else 'a'*64
            raw, trusted_hash = snapshot(**{field: value})
            self.reject(s.SourceProblem.UNTRUSTED_CAPTURE, self.read_offline, raw, expected=trusted_hash)
        # A correctly self-hashed file with no independently configured permit is not readable.
        self.reject(s.SourceProblem.UNTRUSTED_CAPTURE, s.AssignmentSource(REQUEST,
            _reader=lambda *_: raw).read, OFFLINE_MODE)

    # WORK_UNIT_CASE: 849/35
    def test_declared_denominator_disagreement_or_absence_is_invalid(self):
        for body in (BODY.replace('2 cases', '1 cases'), BODY.replace('1..2', '1..3'),
                     BODY.replace('2 cases', '1000000 cases'),
                     BODY.replace('**Declared denominator: 2 cases, exactly 1..2.**', 'No count declared'),
                     BODY.replace('2. Reject', 'When all 3 cases are green this unit is done.\n2. Reject')):
            self.reject(s.SourceProblem.MATRIX_DENOMINATOR, self.parse, body)

    # WORK_UNIT_CASE: 849/36
    def test_unicode_crlf_json_escaping_and_unclosed_parse_states(self):
        body = BODY.replace('current identity.', 'точную идентичность café \\ "quoted".').replace('\n', '\r\n')
        result = acquire(LIVE | {'body': body})
        self.assertEqual(hashlib.sha256(body.encode()).hexdigest(), result.receipt.body_sha256)
        self.assertEqual(body, result.body)
        self.assertNotEqual(hashlib.sha256(json.dumps(LIVE | {'body': body}).encode()).hexdigest(), result.receipt.body_sha256)
        for item in result.matrix.cases:
            self.assertEqual(item.text.encode(), body.encode()[item.start_byte:item.end_byte])
        self.reject(s.SourceProblem.ENCODING, acquire, observed=response(body=b'\xff'))
        self.reject(s.SourceProblem.ENCODING, acquire, LIVE | {'body': '\ud800'})
        self.reject(s.SourceProblem.MARKDOWN, self.parse, BODY + '```\nunclosed')
        self.reject(s.SourceProblem.MARKDOWN, self.parse, BODY + '<!-- unterminated')


class BoundaryRegressionTests(unittest.TestCase):
    reject = SourceTests.reject
    parse = SourceTests.parse
    read_offline = SourceTests.read_offline

    def test_delayed_io_has_one_slot_and_cannot_deliver_late_success(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        calls = []
        def blocked(*_):
            calls.append(1); entered.set()
            try:
                release.wait(2)
                return response()
            finally: finished.set()
        limits = dataclasses.replace(s.SourceLimits(), connect_ms=10, read_ms=10, total_ms=25)
        source = s.AssignmentSource(REQUEST, limits=limits, _transport=blocked)
        try:
            error = self.reject(s.SourceProblem.TIMEOUT, source.read, LIVE_MODE)
            self.assertTrue(entered.is_set()); self.assertTrue(error.cleanup_pending)
            self.reject(s.SourceProblem.BUSY, source.read, LIVE_MODE)
            self.assertEqual([1], calls)
        finally:
            release.set(); self.assertTrue(finished.wait(2))
        self.assertEqual([1], calls)  # No implicit retry or cache refresh.

    def test_controls_and_closed_schema_cannot_be_hidden_in_json(self):
        raw = response().body.replace(b'"number": 849', b'"number": 849, "\\u006eumber": 849')
        self.reject(s.SourceProblem.JSON, acquire, observed=response(body=raw))
        for changes in ({'updated_at': '2026-02-30T00:00:00Z'}, {'labels': 'superseded'}, {'title': '[A-1] \0canary'}):
            with self.assertRaises(s.SourceError): acquire(LIVE | changes)

    def test_offline_rejects_unknown_fields_mode_origin_and_bool_relation(self):
        base = json.loads(OFFLINE); base['extra'] = 'not admitted'
        self.reject(s.SourceProblem.SCHEMA, self.read_offline, json.dumps(base).encode())
        for key, value in (('origin', 'https://other.invalid'), ('source_mode', 'explicit-offline-snapshot')):
            raw, digest = snapshot(**{key: value})
            self.reject(s.SourceProblem.ORIGIN, self.read_offline, raw, expected=digest)
        raw, digest = snapshot(relation={'source': 849, 'target': True, 'role': 'blocked-by'})
        self.reject(s.SourceProblem.SCHEMA, self.read_offline, raw, expected=digest)

    def test_closed_prerequisite_offline_does_not_become_active(self):
        request = dataclasses.replace(REQUEST, source_use=c.AssignmentSourceUse.PREREQUISITE_EVIDENCE)
        raw, digest = snapshot(source_use=request.source_use.value, state='closed')
        result = self.read_offline(raw, expected=digest, request=request)
        self.assertIs(result.receipt.state, c.IssueState.CLOSED)
        raw, digest = snapshot(source_use=request.source_use.value, state='superseded')
        result = self.read_offline(raw, expected=digest, request=request)
        self.assertIs(result.receipt.state, c.IssueState.SUPERSEDED)

    def test_file_link_and_special_file_are_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root/'capture.json'; target.write_bytes(OFFLINE)
            link = root/'alias.json'
            try: link.symlink_to(target)
            except (OSError, NotImplementedError):
                with patch.object(s.os, 'open', side_effect=OSError('unsupported link')):
                    self.reject(s.SourceProblem.FILE, s._read_capture, link, 10000)
            else:
                self.reject(s.SourceProblem.FILE, s._read_capture, link, 10000)
            self.reject(s.SourceProblem.FILE, s._read_capture, root, 10000)
            self.reject(s.SourceProblem.FILE, s._read_capture, root/'absent-canary', 10000)
            if os.name == 'posix':
                fifo = root/'fifo'; os.mkfifo(fifo)
                self.reject(s.SourceProblem.FILE, s._read_capture, fifo, 10000)

    def test_read_cap_and_identity_are_checked_on_actual_opened_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'capture.json'; path.write_bytes(OFFLINE)
            self.reject(s.SourceProblem.RESPONSE_LIMIT, s._read_capture, path, len(OFFLINE)-1)
            self.assertEqual(OFFLINE, s._read_capture(path, len(OFFLINE)))
        self.reject(s.SourceProblem.CONFIGURATION, s.TrustedOfflineCapture, REQUEST,
            Path('relative.json'), CAPTURE_SHA, c.WorkUnitIdentity('controller'), 'e'*64, 'f'*64, 600)

    def test_limits_and_modes_are_exact_typed_and_bounded(self):
        for field in s.SourceLimits.__dataclass_fields__:
            for invalid in (0, -1, True, 1.5, 10**10):
                self.reject(s.SourceProblem.CONFIGURATION, dataclasses.replace, s.SourceLimits(), **{field: invalid})
        self.reject(s.SourceProblem.CONFIGURATION, s.AssignmentSource, REQUEST, token_env='ARBITRARY_SECRET')
        for token in ('', 'bad\r\nHeader: x', 'x'*513):
            with patch.dict(os.environ, {'GITHUB_TOKEN': token}):
                self.reject(s.SourceProblem.AUTH, s.AssignmentSource(REQUEST, token_env='GITHUB_TOKEN',
                    _transport=lambda *_: self.fail('bad token reached network')).read, LIVE_MODE)

    def test_unsupported_html_bare_cr_and_malformed_number_labels_fail(self):
        for body in (BODY.replace('1. Accept', '01. Accept'), BODY.replace('1. Accept', '١. Accept'),
                     BODY.replace('1. Accept', '1: Accept'), BODY.replace('1. Accept', '1.Accept')):
            self.reject(s.SourceProblem.MATRIX_NUMBERING, self.parse, body)
        self.reject(s.SourceProblem.MARKDOWN, self.parse, BODY.replace('\n', '\r'))
        self.reject(s.SourceProblem.MARKDOWN, self.parse, '<div>\n' + BODY + '</div>')
        self.reject(s.SourceProblem.MATRIX_EMPTY, self.parse, BODY.replace('1. Accept the exact current identity.', '1. '))

    def test_no_new_schema_or_secret_fields_enter_canonical_receipt(self):
        document = acquire()
        with self.assertRaises(dataclasses.FrozenInstanceError): document.body = 'changed'
        self.assertEqual('eliot-work-unit-contracts-v4', c.CONTRACT_SCHEMA_REVISION)
        self.assertNotIn('token', {field.name for field in dataclasses.fields(document.receipt)})
        self.assertNotIn('accepted_commit', {field.name for field in dataclasses.fields(document.receipt)})
        self.assertEqual(document.matrix.body_sha256, document.receipt.body_sha256)

    def test_body_change_invalidates_a_real_v4_descriptor_binding(self):
        document = acquire(); changed = acquire(LIVE | {'body': BODY + '\nnew outside-matrix instruction'})
        descriptor = c.WorkUnitDescriptor(c.WORK_UNIT_DESCRIPTOR_SCHEMA, c.DescriptorIdentity('849-source'), ISSUE,
            REQUEST.unit, c.RunnerMode.PYTHON_UNITTEST, (c.RepositoryPath('scripts/work_unit_gate/assignment_source.py'),),
            (c.RepositoryPath('scripts/tests/test_work_unit_assignment_source.py'),), 2, c.ProofCeiling('source-only'),
            1, document.receipt.body_sha256, document.receipt.matrix_sha256, False,
            c.VerificationRequirements(1,0,2,()), c.ExecutionBounds(20000,5000,65536,4096,100,1))
        self.assertEqual(document.receipt.matrix_sha256, changed.receipt.matrix_sha256)
        with self.assertRaises(c.ContractViolation):
            c.SourceShapeGateReceipt(changed.receipt, descriptor, c.OverallResult.PASS, (), descriptor.proof_ceiling,
                                     'a'*64, 1, 0, 2, ())

    def test_http_content_length_and_output_caps_precede_decode(self):
        class Sock:
            def settimeout(self, *_): pass
        class Reply:
            status=200
            def getheaders(self): return [('content-type','application/json'), ('content-length','99999999')]
            def read1(self, *_): raise AssertionError('oversized body was read')
        class Connection:
            sock=Sock()
            def __init__(self,*_,**kw): pass
            def connect(self): pass
            def request(self,*_,**kw): pass
            def getresponse(self): return Reply()
            def close(self): pass
        with patch.object(s.http.client,'HTTPSConnection',Connection):
            self.reject(s.SourceProblem.RESPONSE_LIMIT,s._https_get,REQUEST,s.SourceLimits(),None)
        self.reject(s.SourceProblem.MEDIA,acquire,observed=response(headers=(('content-type','application/json'),('content-encoding','gzip'))))

    def test_capture_expiring_during_validation_is_not_delivered(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.json'
            path.write_bytes(OFFLINE)
            permit = s.TrustedOfflineCapture(REQUEST, path, CAPTURE_SHA,
                c.WorkUnitIdentity('controller'), 'e'*64, 'f'*64, 600)
            moments = iter((1599, 1600))
            source = s.AssignmentSource(REQUEST, offline=permit, clock=lambda: next(moments),
                _transport=lambda *_: self.fail('offline accessed network'))
            self.reject(s.SourceProblem.CAPTURE_STALE, source.read, OFFLINE_MODE)

    def test_exact_case_line_body_and_response_boundaries(self):
        matrix = self.parse(BODY)
        largest_case = max(len(item.text.encode()) for item in matrix.cases)
        largest_line = max(len(line.encode()) for line in BODY.splitlines(keepends=True))
        for name, exact in (('case_bytes', largest_case), ('line_bytes', largest_line)):
            self.assertEqual(matrix, self.parse(BODY, dataclasses.replace(s.SourceLimits(), **{name: exact})))
            self.reject(s.SourceProblem.STRUCTURE_LIMIT, self.parse, BODY,
                        dataclasses.replace(s.SourceLimits(), **{name: exact-1}))
        body_limit = len(BODY.encode())
        limits = s.SourceLimits(body_bytes=body_limit, line_bytes=largest_line, case_bytes=largest_case)
        self.assertEqual(matrix, self.parse(BODY, limits))
        self.reject(s.SourceProblem.BODY_LIMIT, self.parse, BODY + 'x', limits)
        size = len(response().body)
        limits = dataclasses.replace(limits, response_bytes=size)
        self.assertEqual(matrix, acquire(limits=limits).matrix)
        self.reject(s.SourceProblem.RESPONSE_LIMIT, acquire,
                    limits=dataclasses.replace(limits, response_bytes=size-1))

    def test_exact_once_marker_mapping_and_no_mutation_or_subprocess_surface(self):
        path=ROOT/'scripts/tests/test_work_unit_assignment_source.py'
        tree=ast.parse(path.read_text()); lines=path.read_text().splitlines()
        markers={}
        for node in ast.walk(tree):
            if isinstance(node,ast.FunctionDef) and node.name.startswith('test_'):
                text=lines[node.lineno-2].strip() if node.lineno>1 else ''
                if text.startswith('# WORK_UNIT_CASE: 849/'):
                    number=int(text.rsplit('/',1)[1]); self.assertNotIn(number,markers); markers[number]=node.name
        self.assertEqual(set(range(1,37)),set(markers))
        tree=ast.parse((ROOT/'scripts/work_unit_gate/assignment_source.py').read_text())
        imported={a.name.split('.')[0] for n in ast.walk(tree) if isinstance(n,ast.Import) for a in n.names}
        self.assertTrue(imported.isdisjoint({'subprocess','requests','pickle'}))
        methods={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertTrue(methods.isdisjoint({'write_text','write_bytes','mkdir','unlink','rename','system','popen'}))
        # str.replace in Markdown parsing is not filesystem replacement.
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr == 'replace':
                receiver = node.func.value
                while isinstance(receiver,ast.Call) and isinstance(receiver.func,ast.Attribute):
                    receiver = receiver.func.value
                self.assertIsInstance(receiver, ast.Name)
                self.assertEqual('text', receiver.id)


class HeadingCompatibilityTests(unittest.TestCase):
    """#818's finite heading table at the actual #849 acquisition boundary.

    Additional regressions preserve all original 36 primary case bindings.
    Captured matrix text is data, never a trusted offline authority receipt.
    """
    reject = SourceTests.reject
    parse = SourceTests.parse
    ALIASES = ('Required test matrix', 'Deterministic acceptance matrix',
               'Repair and acceptance contract')

    def test_finite_alias_table_has_exactly_the_three_accepted_names(self):
        self.assertEqual(frozenset(name.lower() for name in self.ALIASES), s.MATRIX_HEADING_ALIASES)
        self.assertEqual('eliot-assignment-matrix-headings-v2', s.MATRIX_HEADING_POLICY)
        self.assertEqual('eliot-assignment-matrix-v1', s.MATRIX_SCHEMA)
        with self.assertRaises(TypeError):
            s.parse_matrix(BODY, ISSUE, heading_aliases=('arbitrary acceptance',))

    def test_each_alias_works_through_the_real_acquisition_path(self):
        expected = self.parse(BODY)
        for alias in self.ALIASES:
            with self.subTest(alias=alias):
                body = BODY.replace('Required test matrix', alias)
                result = acquire(LIVE | {'body': body})
                self.assertEqual([1, 2], [case.identity.number for case in result.matrix.cases])
                self.assertEqual(expected.matrix_sha256, result.receipt.matrix_sha256)
                self.assertEqual(hashlib.sha256(body.encode()).hexdigest(), result.receipt.body_sha256)
                self.assertEqual(body, result.body)

    def test_case_horizontal_whitespace_and_balanced_outer_decoration(self):
        expected = self.parse(BODY)
        for alias in self.ALIASES:
            for wrapper in ('', '*', '**', '_', '__'):
                for closing in ('', ' ###'):
                    heading = '##\t' + wrapper + alias.upper().replace(' ', ' \t ') + wrapper + closing + '  '
                    with self.subTest(heading=heading):
                        body = BODY.replace('## Required test matrix', heading)
                        result = self.parse(body)
                        self.assertEqual(expected.matrix_sha256, result.matrix_sha256)
                        self.assertEqual(hashlib.sha256(body.encode()).hexdigest(), result.body_sha256)

    def test_near_matches_and_inline_code_are_not_matrix_authority(self):
        for title in ('Acceptance criteria', 'Required result', 'Verification and acceptance',
                      'Examples of required test matrix', 'Required test matrix examples',
                      'Required test matrix:', '`Required test matrix`',
                      '[Required test matrix](https://example.invalid)',
                      '**Required test matrix', 'Required **test** matrix',
                      '***Required test matrix***', 'Required\u00a0test matrix'):
            with self.subTest(title=title):
                self.reject(s.SourceProblem.MATRIX_MISSING, self.parse,
                            BODY.replace('Required test matrix', title))

    def test_mixed_duplicate_aliases_fail_even_after_verification_section(self):
        for first in self.ALIASES:
            for second in self.ALIASES:
                with self.subTest(first=first, second=second):
                    body = BODY.replace('Required test matrix', first)
                    body += '\n## **' + second.upper() + '**\n1. Ambiguous second matrix.\n'
                    self.reject(s.SourceProblem.MATRIX_MULTIPLE, self.parse, body)

    def test_every_alias_at_wrong_heading_level_fails(self):
        for alias in self.ALIASES:
            for level in (1, 3, 4, 5, 6):
                with self.subTest(alias=alias, level=level):
                    self.reject(s.SourceProblem.MATRIX_HEADING, self.parse,
                                BODY.replace('## Required test matrix', '#' * level + ' ' + alias))

    def test_hidden_aliases_do_not_supply_or_duplicate_a_matrix(self):
        for alias in self.ALIASES:
            heading = '## **' + alias + '**'
            hidden = ('```\n' + heading + '\n1. Example.\n```\n',
                      '> ' + heading + '\n> 1. Example.\n',
                      '    ' + heading + '\n    1. Example.\n',
                      '\t' + heading + '\n\t1. Example.\n')
            for block in hidden:
                with self.subTest(alias=alias, block=block[:8]):
                    self.assertEqual(2, len(self.parse(block + BODY).cases))
                    self.reject(s.SourceProblem.MATRIX_MISSING, self.parse, block)

    def test_indented_heading_is_not_promoted_from_nested_content(self):
        for spaces in (1, 2, 3):
            self.reject(s.SourceProblem.MATRIX_MISSING, self.parse,
                        BODY.replace('## Required test matrix', ' ' * spaces + '## Required test matrix'))

    def test_declared_count_and_numbering_guards_apply_to_every_alias(self):
        for alias in self.ALIASES:
            base = BODY.replace('Required test matrix', alias)
            for body in (base.replace('2 cases', '1 cases'), base.replace('1..2', '1..3')):
                self.reject(s.SourceProblem.MATRIX_DENOMINATOR, self.parse, body)
            for body in (base.replace('1. Accept', '0. Accept'), base.replace('2. Reject', '1. Reject'),
                         base.replace('2. Reject', '3. Reject')):
                self.reject(s.SourceProblem.MATRIX_NUMBERING, self.parse, body)

    def test_alias_does_not_replace_missing_count_or_empty_case_sequence(self):
        for alias in self.ALIASES:
            self.reject(s.SourceProblem.MATRIX_DENOMINATOR, self.parse,
                        '## ' + alias + '\n1. Real obligation.\n')
            self.reject(s.SourceProblem.MATRIX_EMPTY, self.parse,
                        '## ' + alias + '\nDeclared denominator: 1 case.\n')

    def test_exact_crlf_unicode_case_spans_are_not_normalized(self):
        for alias in self.ALIASES:
            body = BODY.replace('Required test matrix', alias).replace('current identity.',
                    'точную идентичность café.').replace('\n', '\r\n')
            parsed = self.parse(body)
            for case in parsed.cases:
                self.assertEqual(case.text.encode(), body.encode()[case.start_byte:case.end_byte])
                self.assertIn('\r\n', case.text)
            self.assertEqual(hashlib.sha256(body.encode()).hexdigest(), parsed.body_sha256)

    def test_heading_only_change_keeps_matrix_but_invalidates_body_bound_descriptor(self):
        first = acquire()
        changed = acquire(LIVE | {'body': BODY.replace('Required test matrix', 'Repair and acceptance contract')})
        self.assertEqual(first.receipt.matrix_sha256, changed.receipt.matrix_sha256)
        self.assertNotEqual(first.receipt.body_sha256, changed.receipt.body_sha256)
        descriptor = c.WorkUnitDescriptor(c.WORK_UNIT_DESCRIPTOR_SCHEMA, c.DescriptorIdentity('849-source'), ISSUE,
            REQUEST.unit, c.RunnerMode.PYTHON_UNITTEST, (c.RepositoryPath('scripts/work_unit_gate/assignment_source.py'),),
            (c.RepositoryPath('scripts/tests/test_work_unit_assignment_source.py'),), 2, c.ProofCeiling('source-only'),
            1, first.receipt.body_sha256, first.receipt.matrix_sha256, False,
            c.VerificationRequirements(1, 0, 2, ()), c.ExecutionBounds(20000, 5000, 65536, 4096, 100, 1))
        with self.assertRaises(c.ContractViolation):
            c.SourceShapeGateReceipt(changed.receipt, descriptor, c.OverallResult.PASS, (), descriptor.proof_ceiling,
                                     'a'*64, 1, 0, 2, ())

    def test_actual_840_section_retains_all_ten_original_obligations(self):
        fixture = json.loads((FIXTURES / 'heading-compatibility.json').read_text(encoding='utf-8'))
        body = fixture['excerpt']
        issue = c.IssueIdentity(c.RepositoryIdentity('UnknownAlienHuman', 'eliot-memory-os'), 840)
        parsed = s.parse_matrix(body, issue)
        self.assertEqual(list(range(1, 11)), fixture['expected_cases'])
        self.assertEqual(fixture['expected_cases'], [case.identity.number for case in parsed.cases])
        self.assertEqual(fixture['excerpt_sha256'], hashlib.sha256(body.encode()).hexdigest())
        self.assertTrue(parsed.cases[0].text.startswith('1. baseline failure is the obsolete literal'))
        self.assertTrue(parsed.cases[9].text.startswith('10. product diff is solely the stale assertion removal'))
        self.assertNotIn('## Verification', parsed.cases[9].text)
        for case in parsed.cases:
            self.assertEqual(issue, case.identity.issue)
            self.assertEqual(case.text.encode(), body.encode()[case.start_byte:case.end_byte])
        # An excerpt is not an offline source receipt and cannot admit itself.
        self.reject(s.SourceProblem.UNTRUSTED_CAPTURE, s.AssignmentSource(REQUEST).read, OFFLINE_MODE)

    def test_real_840_shape_is_acquired_without_renaming_its_heading(self):
        fixture = json.loads((FIXTURES / 'heading-compatibility.json').read_text(encoding='utf-8'))
        issue = c.IssueIdentity(c.RepositoryIdentity('UnknownAlienHuman', 'eliot-memory-os'), 840)
        request = s.SourceRequest(issue, c.WorkUnitIdentity('D-TEST-CLI-CONTRACT'), c.AssignmentSourceUse.ACTIVE_ASSIGNMENT)
        # This finite transport fixture exercises the real production decoder;
        # it is not evidence that the module made a live GitHub HTTPS request.
        payload = LIVE | {'number': 840, 'title': '[D-TEST-CLI-CONTRACT] Remove the stale duplicated MCP version assertion',
            'url': request.endpoint, 'repository_url': 'https://api.github.com/repos/UnknownAlienHuman/eliot-memory-os',
            'html_url': fixture['source_url'], 'body': fixture['excerpt'], 'updated_at': fixture['source_updated_at']}
        result = acquire(payload, request=request, observed=response(payload=payload, url=request.endpoint))
        self.assertEqual(10, result.receipt.matrix_cases)
        self.assertEqual(request.unit, result.receipt.unit)
        self.assertEqual('assignment-source-only', result.receipt.proof_ceiling.value)

    def test_empty_major_heading_ends_matrix_before_unrelated_numbering(self):
        for separator in ('#', '##', '##  ', '# ###'):
            body = BODY.replace('## Verification', separator) + '99. Outside the matrix.\n'
            parsed = self.parse(body)
            self.assertEqual(2, len(parsed.cases))
            self.assertNotIn('99. Outside', parsed.cases[-1].text)
            self.assertNotIn('No live effects', parsed.cases[-1].text)

    def test_subheading_group_preserves_numbering_and_case_boundaries(self):
        for alias in self.ALIASES:
            body = BODY.replace('Required test matrix', alias).replace('2. Reject', '### **Second group** ###\n2. Reject')
            parsed = self.parse(body)
            self.assertEqual([1, 2], [case.identity.number for case in parsed.cases])
            self.assertNotIn('Second group', parsed.cases[0].text)
            self.assertTrue(parsed.cases[1].text.startswith('2. Reject'))


if __name__ == '__main__':
    unittest.main()
