"""Marker-bearing suite for 837 binding checks (real #851 parse, tiny)."""
import unittest


class Markers(unittest.TestCase):
    # WORK_UNIT_CASE: 837/1
    def test_selected_one(self):
        self.assertTrue(True)

    # WORK_UNIT_CASE: 837/2
    def test_selected_two(self):
        self.assertTrue(True)
