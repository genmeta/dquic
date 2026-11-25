import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ci import MEASUREMENTS, TESTS, check_results, main


def result(measurements=False):
    return {
        "clients": ["dquic"],
        "servers": ["quic-go"],
        "results": [[{"name": name, "result": "succeeded"} for name in TESTS]],
        "measurements": [[
            {"name": name, "result": "succeeded", "details": "9500 kbps"}
            for name in (MEASUREMENTS if measurements else ())
        ]],
    }


class ResultCheck(unittest.TestCase):
    def test_complete_matrix(self):
        rows, passed = check_results(result(), "dquic", "quic-go")
        self.assertEqual(len(rows), len(TESTS))
        self.assertTrue(passed)

    def test_wrong_direction_is_rejected(self):
        with self.assertRaises(ValueError):
            check_results(result(), "quic-go", "dquic")

    def test_incomplete_and_duplicate_matrices_are_rejected(self):
        for category in ("results", "measurements"):
            for change in ("missing_group", "missing_test", "duplicate_test"):
                with self.subTest(category=category, change=change):
                    data = result(measurements=True)
                    if change == "missing_group":
                        data[category] = []
                    elif change == "missing_test":
                        data[category][0].pop()
                    else:
                        data[category][0][-1] = data[category][0][0]
                    with self.assertRaises(ValueError):
                        check_results(data, "dquic", "quic-go", measurements=True)

    def test_failed_unsupported_and_unrun_checks_remain_unsuccessful(self):
        for category in ("results", "measurements"):
            for status in ("failed", "unsupported", None):
                with self.subTest(category=category, status=status):
                    data = result(measurements=True)
                    data[category][0][0]["result"] = status
                    _, passed = check_results(data, "dquic", "quic-go", measurements=True)
                    self.assertFalse(passed)

    def test_measurements_are_required_when_enabled(self):
        with self.assertRaises(ValueError):
            check_results(result(), "dquic", "quic-go", measurements=True)
        rows, passed = check_results(result(measurements=True), "dquic", "quic-go", measurements=True)
        self.assertTrue(passed)
        self.assertEqual(rows[-1], ("crosstraffic", "succeeded", "9500 kbps"))

    def test_msquic_runs_both_directions_and_retains_server_readiness_rules(self):
        waits = {}

        def run(command, **options):
            if "run.py" in command:
                client = command[command.index("-c") + 1]
                server = command[command.index("-s") + 1]
                waits[server] = options.get("env", {}).get("INTEROP_WAIT_FOR_SERVER")
                data = result()
                data.update(clients=[client], servers=[server])
                Path(command[command.index("-j") + 1]).write_text(json.dumps(data))
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "implementations_quic.json").write_text(json.dumps({"msquic": {"image": "test:local"}}))
            args = ["ci.py", str(root), "msquic", "--output", str(root / "output")]
            with (
                patch("sys.argv", args),
                patch("ci.subprocess.run", side_effect=run),
                patch("builtins.print"),
                patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(root / "summary.md")}),
            ):
                self.assertEqual(main(), 0)
            self.assertIn("INTEROP_WAIT_FOR_SERVER", (root / "docker-compose.override.yml").read_text())
        self.assertEqual(waits, {"msquic": "server:443", "dquic": ""})


if __name__ == "__main__":
    unittest.main()
