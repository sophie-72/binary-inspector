import subprocess
import unittest


class TestBinaryInspector(unittest.TestCase):
    def test_main_runs_correctly(self):
        command = ["python", "-m", "src.main", "example/example"]
        result = subprocess.run(command, check=True)

        self.assertEqual(result.returncode, 0)
