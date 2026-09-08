"""Windows nested-tree reap fixture for #850.

The single test spawns a fixed `powershell -NoProfile -Command
"Start-Sleep -Seconds 60"` grandchild, then blocks in test code so a bounded
launcher cancellation at ~3s must reap the whole owned tree. The test itself
would assert true if it were ever allowed to finish; the matrix expects a
timeout with a verified-zero cleanup disposition instead.
"""
import subprocess
import time
import unittest


class Suite(unittest.TestCase):
    def test_bridge(self):
        proc = subprocess.Popen(
            ["powershell", "-NoProfile", "-Command", "Start-Sleep -Seconds 60"]
        )
        try:
            time.sleep(60)
        finally:
            pass
        self.assertTrue(True)
