import json
from pathlib import Path
import tempfile
import unittest

from ci import TESTS
from report import PEERS, render_report


RUN = {"id": 12, "run_attempt": 1, "head_sha": "a" * 40,
       "html_url": "https://github.com/genmeta/dquic/actions/runs/12", "conclusion": "failure"}


def write_results(root, peer, client, server, status="succeeded", details=""):
    directory = root / f"interop-results-{peer}"
    directory.mkdir(exist_ok=True)
    data = {"clients": [client], "servers": [server],
            "results": [[{"name": name, "result": status, "details": details} for name in TESTS]],
            "measurements": [[]]}
    path = directory / f"{server}_{client}.json"
    path.write_text(json.dumps(data))
    return path


class ReportCheck(unittest.TestCase):
    def test_complete_matrix_and_job_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for peer in PEERS:
                write_results(root, peer, "dquic", peer)
                write_results(root, peer, peer, "dquic")
            report = render_report(root, dict(RUN, conclusion="success"), [
                {"name": "image", "conclusion": "success", "html_url": RUN["html_url"] + "/job/1"},
                {"name": "interop (quic-go)", "conclusion": "success", "html_url": RUN["html_url"] + "/job/2"},
            ])
        self.assertIn("130 passed · 0 failed · 0 unsupported · 0 missing", report)
        self.assertIn("[image: success]", report)
        self.assertIn("/job/1", report)
        self.assertIn("[quic-go: success]", report)
        self.assertIn("/job/2", report)
        self.assertIn("dquic → quic-go", report)
        self.assertIn("quic-go → dquic", report)

    def test_partial_matrix_keeps_failures_unsupported_and_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_results(root, "quic-go", "dquic", "quic-go")
            data = json.loads(path.read_text())
            data["results"][0][0]["result"] = "failed"
            data["results"][0][1]["result"] = "unsupported"
            data["results"][0][2]["result"] = None
            path.write_text(json.dumps(data))
            report = render_report(root, RUN, [])
        self.assertIn("10 passed · 1 failed · 1 unsupported · 118 missing", report)
        self.assertIn("❌", report)
        self.assertIn("➖", report)
        self.assertIn("❓", report)

    def test_invalid_results_are_never_counted_as_passes(self):
        for change in ("duplicate", "wrong_direction", "invalid_json", "missing_measurements"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = write_results(root, "quic-go", "dquic", "quic-go")
                data = json.loads(path.read_text())
                if change == "duplicate":
                    data["results"][0][-1] = data["results"][0][0]
                elif change == "wrong_direction":
                    data["clients"] = ["quic-go"]
                elif change == "missing_measurements":
                    data.pop("measurements")
                path.write_text("{" if change == "invalid_json" else json.dumps(data))
                report = render_report(root, RUN, [])
                self.assertIn("0 passed · 0 failed · 0 unsupported · 130 missing", report)
                self.assertIn("Missing or invalid results", report)

    def test_untrusted_details_cannot_inject_markup_or_mentions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_results(root, "quic-go", "dquic", "quic-go", "failed",
                          "</details>\n| [click](https://example.com) @someone `code` " + "x" * 10000)
            report = render_report(root, RUN, [])
        self.assertNotIn("@someone", report)
        self.assertNotIn("[click]", report)
        self.assertNotIn("https://example.com)", report)
        self.assertIn("&lt;/details&gt;", report)
        self.assertLess(len(report), 60000)

    def test_unknown_and_nonstring_statuses_remain_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_results(root, "quic-go", "dquic", "quic-go")
            data = json.loads(path.read_text())
            for entry, status in zip(data["results"][0], ("unknown", {"succeeded": True}, ["succeeded"])):
                entry["result"] = status
            path.write_text(json.dumps(data))
            report = render_report(root, RUN, [])
        self.assertIn("10 passed · 0 failed · 0 unsupported · 120 missing", report)


if __name__ == "__main__":
    unittest.main()
