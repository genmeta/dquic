#!/usr/bin/env python3
"""Run the built C3 firmware and fail unless every validation marker appears."""
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time

root = Path(__file__).resolve().parents[1]
binary = sys.argv[1] if len(sys.argv) == 2 else "dependencies"
if binary not in ("dependencies", "echo"):
    raise SystemExit("usage: python tools/qemu.py [dependencies|echo]")
tools = root / ".embuild/espressif"
sdk = tools / "esp-idf/v5.4.2"
builds = list((root / "target/riscv32imc-esp-espidf/debug/build").glob("esp-idf-sys-*/out/build/flasher_args.json"))
if not builds:
    raise SystemExit("build the firmware first")
sdk_build = max(builds, key=lambda p: p.stat().st_mtime).parent
flash_args = json.loads((sdk_build / "flasher_args.json").read_text())
python = next(tools.glob("python_env/idf5.4_py*_env/bin/python"))
qemu = shutil.which("qemu-system-riscv32")
if not qemu:
    qemu = next(tools.glob("tools/qemu-riscv32/*/qemu/bin/qemu-system-riscv32"), None)
if not qemu:
    raise SystemExit("install Espressif qemu-riscv32 with idf_tools.py first")
output = root / "target/qemu"
output.mkdir(exist_ok=True)
image = output / f"{binary}.bin"
flash = output / f"{binary}-flash.bin"
partition_table = output / "partition-table.bin"
elf = root / "target/riscv32imc-esp-espidf/debug" / binary
subprocess.run([str(python), str(sdk / "components/partition_table/gen_esp32part.py"), str(root / "partitions.csv"), str(partition_table)], check=True)
subprocess.run([str(python), "-m", "esptool", "--chip", "esp32c3", "elf2image", "--flash_size", "4MB", "-o", str(image), str(elf)], check=True)
merge = [str(python), "-m", "esptool", "--chip", "esp32c3", "merge_bin", "--fill-flash-size", "4MB", "-o", str(flash)]
for offset, file in flash_args["flash_files"].items():
    path = image if offset == flash_args["app"]["offset"] else sdk_build / file
    if offset == flash_args["partition-table"]["offset"]:
        path = partition_table
    merge += [offset, str(path)]
subprocess.run(merge, check=True)

# Reuse ESP-IDF's target-specific eFuse defaults, including C3 revision 0.3.
sys.path.insert(0, str(sdk / "tools"))
from idf_py_actions.qemu_ext import QEMU_TARGETS

efuse = output / "efuse.bin"
efuse.write_bytes(QEMU_TARGETS["esp32c3"].default_efuse)
command = [str(qemu), "-M", "esp32c3", "-nographic", "-no-reboot", "-nic", "none",
           "-drive", f"file={flash},if=mtd,format=raw",
           "-drive", f"file={efuse},if=none,format=raw,id=efuse",
           "-global", "driver=nvram.esp32c3.efuse,property=drive,value=efuse",
           "-global", "driver=timer.esp32c3.timg,property=wdt_disable,value=true"]
markers = ["PASS: Tokio UDP loopback", "PASS: qtls QUIC TLS handshake"] if binary == "dependencies" else [
    "PASS: pointer-sized counters wrap and preserve sampled deltas",
    "PASS: qudp datagram boundaries, truncation and buffer reuse",
    "PASS: verified QUIC handshake", "PASS: bidirectional echo"]
markers += ["Returned from app_main()"]
captured = b""
deadline = time.monotonic() + 90
with (output / f"{binary}.log").open("wb") as log:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    try:
        while time.monotonic() < deadline:
            if select.select([process.stdout], [], [], 0.5)[0]:
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                captured += chunk
                log.write(chunk)
                log.flush()
                print(chunk.decode(errors="replace"), end="", flush=True)
                if all(marker.encode() in captured for marker in markers):
                    print(f"PASS: {binary} firmware completed in ESP32-C3 QEMU", flush=True)
                    break
            elif process.poll() is not None:
                break
        else:
            raise SystemExit("QEMU validation timed out")
        missing = [marker for marker in markers if marker.encode() not in captured]
        if missing:
            raise SystemExit(f"QEMU validation failed; missing: {missing}")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
