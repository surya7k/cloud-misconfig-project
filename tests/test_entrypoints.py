import subprocess
import sys
import unittest


class EntrypointTests(unittest.TestCase):
    def test_predict_script_direct_execution_loads_imports(self):
        result = subprocess.run(
            [sys.executable, "src/predict.py"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("Usage: python src/predict.py <config.json>", result.stdout)
        self.assertNotIn("ModuleNotFoundError", result.stderr)


if __name__ == "__main__":
    unittest.main()
