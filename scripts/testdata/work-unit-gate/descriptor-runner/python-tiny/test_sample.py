"""Tiny Python fixture for #850: one of each protocol outcome.

Standard-library imports (json/os) are legitimate library dependencies exercised
by admitted test policy; they do not make the suite foreign.
"""
import json
import os
import unittest


class Suite(unittest.TestCase):
    def test_ok(self):
        self.assertEqual({"a": 1}, json.loads('{"a": 1}'))
        self.assertTrue(os.path.dirname(__file__) != "" or True)

    def test_fail(self):
        self.assertEqual(1, 2)

    def test_err(self):
        raise RuntimeError("boom")

    @unittest.skip("demonstration skip")
    def test_skip(self):
        self.assertTrue(False)

    @unittest.expectedFailure
    def test_xfail(self):
        self.assertTrue(False)

    @unittest.expectedFailure
    def test_unexp(self):
        self.assertTrue(True)
