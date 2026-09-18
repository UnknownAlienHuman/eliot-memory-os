"""Finite deterministic placeholder anti-patterns for case binding tests (#851)."""
from __future__ import annotations

import unittest


class PlaceholderTests(unittest.TestCase):
    # WORK_UNIT_CASE: 851/37
    def test_empty_pass(self):
        pass

    # WORK_UNIT_CASE: 851/38
    def test_unconditional_true(self):
        self.assertTrue(True)

    # WORK_UNIT_CASE: 851/39
    def test_trivial_self_equality(self):
        x = 42
        self.assertEqual(x, x)

    # WORK_UNIT_CASE: 851/40
    def test_no_check_constant(self):
        x = 10
        y = [1, 2, 3]
        _ = x + len(y)
