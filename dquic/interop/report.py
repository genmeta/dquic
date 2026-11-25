#!/usr/bin/env python3
"""Render JSON-only Interop Runner artifacts as a PR comment."""

import argparse
from collections import Counter
import html
import json
import os
from pathlib import Path

from ci import PEERS, TESTS, check_results


SYMBOLS = {"succeeded": "✅", "failed": "❌", "unsupported": "➖", "missing": "❓"}


def text(value):
    value = " ".join(str(value).split())[:240]
    value = html.escape(value, quote=False)
    for character in "\\`*_[]()|@":
        value = value.replace(character, f"&#{ord(character)};")
    return value[:400]


def render_report(artifacts, run, jobs):
    counts = Counter()
    table = ["| Peer | Direction | Passed | Failed | Unsupported | Missing |",
             "| --- | --- | ---: | ---: | ---: | ---: |"]
    sections = []
    for peer in PEERS:
        job = next((job for job in jobs if job["name"] == f"interop ({peer})"), None)
        label = f"[{peer}: {text(job['conclusion'])}]({job['html_url']})" if job else peer
        directions = []
        notes = []
        for client, server in (("dquic", peer), (peer, "dquic")):
            path = artifacts / f"interop-results-{peer}" / f"{server}_{client}.json"
            try:
                if path.stat().st_size > 1024 * 1024:
                    raise ValueError("result JSON exceeds 1 MiB")
                rows, _ = check_results(json.loads(path.read_text()), client, server)
            except (OSError, ValueError, KeyError, TypeError) as error:
                rows = [(name, "missing", "") for name in TESTS]
                notes.append(f"{client} → {server}: Missing or invalid results ({text(error)}).")
            results = {}
            for name, status, details in rows:
                status = status if isinstance(status, str) and status in SYMBOLS else "missing"
                results[name] = (status, text(details))
            direction_counts = Counter(status for status, _ in results.values())
            counts.update(direction_counts)
            table.append(f"| {label} | {client} → {server} | " + " | ".join(
                str(direction_counts[status]) for status in SYMBOLS) + " |")
            directions.append(results)
        sections.extend(["<details>", f"<summary>{peer}: individual checks</summary>", "",
                         "| Test | dquic client | dquic server | Details |",
                         "| --- | --- | --- | --- |"])
        for name in TESTS:
            entries = [direction[name] for direction in directions]
            details = "; ".join(f"{role}: {detail}" for role, (_, detail) in
                                zip(("client", "server"), entries) if detail)
            sections.append(f"| {name} | {SYMBOLS[entries[0][0]]} | {SYMBOLS[entries[1][0]]} | {details} |")
        sections.extend(["", *notes, "", "</details>", ""])

    url = run["html_url"]
    conclusion = f" · CI: **{text(run['conclusion'])}**" if run.get("conclusion") else ""
    header = ["## QUIC interop", "",
              f"Commit: `{run['head_sha']}` · [Run {run['id']}, attempt {run['run_attempt']}]({url})"
              f"{conclusion}", "",
              f"**{counts['succeeded']} passed · {counts['failed']} failed · "
              f"{counts['unsupported']} unsupported · {counts['missing']} missing**", ""]
    checks = [f"[{text(job['name'])}: {text(job['conclusion'])}]({job['html_url']})"
              for job in jobs if job["name"] in ("regression", "image")]
    if checks:
        header.extend([" · ".join(checks), ""])
    return "\n".join([
        *header, *table, "", "✅ passed · ❌ failed · ➖ unsupported · ❓ missing/unrun", "",
        *sections,
        "Scope: QUIC v1 and the 13 selected scenarios in both directions. The endpoint supports "
        "16 supplied certificates by default, including the Runner's nine-certificate chain. "
        "Certificate chains, names and signatures remain verified; ocsp-must-staple is disabled to permit missing OCSP.", "",
        "Outside this matrix: Retry, resumption, 0-RTT, HTTP/3, QUIC v2, explicit key-update initiation, "
        "preferred-address migration and ECN. Performance measurements are not included in these counts.", "",
        f"[Full logs, packet captures and TLS key logs]({url}#artifacts) (retained for seven days).", "",
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path)
    parser.add_argument("--run", type=Path, help="Actions run JSON; defaults to the workflow_run event")
    parser.add_argument("--jobs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run = (json.loads(args.run.read_text()) if args.run else
           json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())["workflow_run"])
    report = render_report(args.artifacts, run, json.loads(args.jobs.read_text()))
    args.output.write_text(report)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(path).write_text(report)


if __name__ == "__main__":
    main()
