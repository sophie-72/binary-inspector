import subprocess
import unittest


class TestBinaryInspector(unittest.TestCase):
    def test_main_runs_correctly(self):
        result = subprocess.run(["python", "-m", "src.main", "example/example"])

        self.assertEqual(result.returncode, 0)
