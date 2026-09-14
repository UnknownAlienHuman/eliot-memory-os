"""Tiny bounded Python suite for 837 integration (shape of descriptor-runner python-tiny).

Two passing tests, one failure, one skip. Bounded, offline, stdlib only.
Real discovery/execution goes through accepted #850 APIs in case 837/42.
"""
import unittest


class Suite(unittest.TestCase):
    def test_ok_a(self):
        self.assertEqual(1 + 1, 2)

    def test_ok_b(self):
        self.assertEqual("ab".upper(), "AB")

    def test_fail(self):
        self.assertEqual(1, 2)

    @unittest.skip("demonstration skip stays incomplete, never pass")
    def test_skip(self):
        self.assertTrue(False)
