"""Finite deterministic Python test fixtures for case binding (#851)."""
from __future__ import annotations

import unittest


class SampleTestCase(unittest.TestCase):
    """Docstring containing ignored # WORK_UNIT_CASE: 851/99 marker."""

    # WORK_UNIT_CASE: 851/14
    def test_sample_method(self):
        actual = 10 + 20
        self.assertEqual(actual, 30)

    # WORK_UNIT_CASE: 851/41
    def test_sample_error(self):
        with self.assertRaises(ValueError):
            raise ValueError("expected error")


# WORK_UNIT_CASE: 851/15
def test_metadata_sample():
    value = [1, 2, 3]
    assert len(value) == 3
