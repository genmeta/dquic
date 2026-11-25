#!/usr/bin/env python3
"""Run both Interop Runner directions and require every selected check to pass."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


PEERS = ("quic-go", "ngtcp2", "msquic", "quinn", "aioquic")
TESTS = (
    "handshake", "transfer", "longrtt", "multiplexing", "blackhole",
    "amplificationlimit", "handshakeloss", "transferloss",
    "handshakecorruption", "transfercorruption", "ipv6", "rebind-port",
    "rebind-addr",
)
MEASUREMENTS = ("goodput", "crosstraffic")


def check_results(data, client, server, measurements=False):
    """Reject incomplete matrices as well as unsuccessful test results."""
    if data["clients"] != [client] or data["servers"] != [server]:
        raise ValueError("result does not describe the requested client/server pair")
    rows = []
    for category, expected in (
        ("results", TESTS),
        ("measurements", MEASUREMENTS if measurements else ()),
    ):
        groups = data[category]
        if len(groups) != 1:
            raise ValueError(f"expected exactly one {category} group")
        if sorted(entry["name"] for entry in groups[0]) != sorted(expected):
            raise ValueError(f"missing, duplicate or unexpected {category}")
        for entry in groups[0]:
            rows.append((entry["name"], entry["result"], entry.get("details", "")))
    return rows, all(status == "succeeded" for _, status, _ in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runner", type=Path)
    parser.add_argument("peer", choices=PEERS)
    parser.add_argument("--output", type=Path, default=Path("target/interop"))
    parser.add_argument("--measurements", action="store_true")
    args = parser.parse_args()
    runner = args.runner.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    manifest = runner / "implementations_quic.json"
    implementations = json.loads(manifest.read_text())
    implementations["dquic"] = {
        "image": "dquic-interop:local",
        "url": "https://github.com/genmeta/dquic",
        "role": "both",
    }
    manifest.write_text(json.dumps(implementations, indent=2) + "\n")
    # The simulator's readiness probe requires Version Negotiation, which dquic
    # does not implement yet. Actual handshake tests still verify server readiness.
    (runner / "docker-compose.override.yml").write_text(
        'services:\n  sim:\n    environment:\n      WAITFORSERVER: "${INTEROP_WAIT_FOR_SERVER}"\n'
        '  server:\n    environment:\n      RUST_LOG: "debug"\n'
        '  client:\n    environment:\n      RUST_LOG: "debug"\n'
    )
    images = [implementations[args.peer]["image"], "martenseemann/quic-network-simulator"]
    if args.measurements:
        images.append("martenseemann/quic-interop-iperf-endpoint")
    for image in images:
        subprocess.run(["docker", "pull", image], check=True)
    with (output / "images.json").open("w") as file:
        subprocess.run(["docker", "image", "inspect", "dquic-interop:local", *images], stdout=file, check=True)

    tests = [*TESTS, *(MEASUREMENTS if args.measurements else ())]
    summary = [f"## dquic ↔ {args.peer}", "", "| Client | Server | Test | Result | Details |", "| --- | --- | --- | --- | --- |"]
    failed = False
    for client, server in (("dquic", args.peer), (args.peer, "dquic")):
        name = f"{server}_{client}"
        result = output / f"{name}.json"
        command = [
            sys.executable, "run.py", "-d", "-c", client, "-s", server,
            "-t", ",".join(tests), "-n", f"{client},{server}",
            "-l", str(output / name), "-j", str(result),
        ]
        print("Running:", " ".join(command), flush=True)
        # Run the reverse direction even if this direction fails.
        environment = dict(os.environ, INTEROP_WAIT_FOR_SERVER="" if server == "dquic" else "server:443")
        completed = subprocess.run(command, cwd=runner, env=environment)
        failed |= completed.returncode != 0
        try:
            rows, passed = check_results(json.loads(result.read_text()), client, server, args.measurements)
            failed |= not passed
            for test, status, details in rows:
                summary.append(f"| {client} | {server} | {test} | {status} | {details} |")
        except (OSError, ValueError, KeyError, TypeError) as error:
            summary.append(f"| {client} | {server} | result validation | failed | {error} |")
            failed = True

    report = "\n".join(summary) + "\n"
    (output / "summary.md").write_text(report)
    print(report)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a") as file:
            file.write(report)
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
