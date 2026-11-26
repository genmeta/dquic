#!/usr/bin/env python3
"""Flash and validate the built C6 firmware over native USB Serial/JTAG."""
import json
from pathlib import Path
import subprocess
import sys
import time

import serial
from esptool.reset import HardReset

root = Path(__file__).resolve().parents[1]
if len(sys.argv) != 3 or sys.argv[1] not in ("dependencies", "echo"):
    raise SystemExit("usage: python tools/flash.py [dependencies|echo] PORT")
binary, port = sys.argv[1:]
target = root / "target/riscv32imac-esp-espidf/debug"
elf = target / binary
builds = list((target / "build").glob("esp-idf-sys-*/out/build/flasher_args.json"))
if not elf.is_file() or not builds:
    raise SystemExit("build the firmware with tools/build.py first, selecting esp32c6")
sdk_build = max(builds, key=lambda p: p.stat().st_mtime).parent
flash_args = json.loads((sdk_build / "flasher_args.json").read_text())
if flash_args["extra_esptool_args"]["chip"] != "esp32c6":
    raise SystemExit("SDK build does not target ESP32-C6")
output = root / "target/hardware/esp32c6"
output.mkdir(parents=True, exist_ok=True)
image = output / f"{binary}.bin"
esptool = [sys.executable, "-m", "esptool", "--chip", "esp32c6"]
subprocess.run(esptool + ["elf2image", "--flash_size", flash_args["flash_settings"]["flash_size"],
                          "-o", str(image), str(elf)], check=True)
command = esptool + ["--port", port, "--baud", "921600", "--after", "no_reset",
                     "write_flash"] + flash_args["write_flash_args"]
for offset, file in flash_args["flash_files"].items():
    path = image if offset == flash_args["app"]["offset"] else sdk_build / file
    command += [offset, str(path)]
print(f"Flashing {binary} to ESP32-C6 on {port}", flush=True)
with (output / f"{binary}-flash.log").open("w") as log:
    subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)

markers = ["PASS: Tokio UDP loopback", "PASS: qtls QUIC TLS handshake"] if binary == "dependencies" else [
    "PASS: pointer-sized counters wrap and preserve sampled deltas",
    "PASS: qudp datagram boundaries, truncation and buffer reuse",
    "PASS: verified QUIC handshake", "PASS: bidirectional echo"]
markers += ["Returned from app_main()"]
captured = b""
with serial.Serial(port, 115200, timeout=0.5) as monitor, (output / f"{binary}.txt").open("wb") as log:
    monitor.dtr = False
    monitor.rts = False
    HardReset(monitor, uses_usb=True)()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        chunk = monitor.read(monitor.in_waiting or 1)
        captured += chunk
        log.write(chunk)
        log.flush()
        print(chunk.decode(errors="replace"), end="", flush=True)
        if any(error in captured for error in [b"Guru Meditation Error", b"panicked at", b"abort() was called"]):
            raise SystemExit("ESP32-C6 firmware crashed; see the captured serial log")
        if all(marker.encode() in captured for marker in markers):
            print(f"PASS: {binary} firmware completed on ESP32-C6 hardware", flush=True)
            break
    else:
        missing = [marker for marker in markers if marker.encode() not in captured]
        raise SystemExit(f"ESP32-C6 validation timed out; missing: {missing}")
