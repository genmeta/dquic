#!/usr/bin/env python3
"""Build the dependency probe or echo using an existing or managed ESP-IDF SDK."""
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
os.chdir(root)
binary = sys.argv[1] if len(sys.argv) == 2 else "dependencies"
if binary not in ("dependencies", "echo"):
    raise SystemExit("usage: python3 tools/build.py [dependencies|echo]")

env = os.environ.copy()
env["RUSTC_BOOTSTRAP"] = "1"  # Rust 1.88's build-std; application code is stable.
env.setdefault("CARGO_BUILD_JOBS", "2")
for variable in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH"):
    env.pop(variable, None)
target = root / "target"
target.mkdir(exist_ok=True)
defaults = target / "sdkconfig.defaults"
contents = (root / "sdkconfig.defaults").read_text().replace('"partitions.csv"', '"' + str(root / "partitions.csv") + '"')
if not defaults.exists() or defaults.read_text() != contents:
    defaults.write_text(contents)
env["ESP_IDF_SDKCONFIG_DEFAULTS"] = str(defaults)
env["ESP_IDF_SDKCONFIG"] = str(target / "sdkconfig")
tools = root / ".embuild/espressif"
sdk = tools / "esp-idf/v5.4.2"
gcc = sorted(tools.glob("tools/riscv32-esp-elf/*/riscv32-esp-elf/bin"))
python_env = sorted(tools.glob("python_env/idf5.4_py*_env"))
if sdk.is_dir() and gcc and python_env:
    env["IDF_PATH"] = str(sdk)
    env["IDF_TOOLS_PATH"] = str(tools)
    env["IDF_PYTHON_ENV_PATH"] = str(python_env[-1])
    env["ESP_IDF_TOOLS_INSTALL_DIR"] = "fromenv"
    paths = [python_env[-1] / "bin", gcc[-1], sdk / "tools"]
    env["PATH"] = os.pathsep.join(map(str, paths)) + os.pathsep + env["PATH"]
    roms = sorted(tools.glob("tools/esp-rom-elfs/*"))
    if roms:
        env["ESP_ROM_ELF_DIR"] = str(roms[-1])
    if "LIBCLANG_PATH" not in env and Path("/Library/Developer/CommandLineTools/usr/lib/libclang.dylib").exists():
        env["LIBCLANG_PATH"] = "/Library/Developer/CommandLineTools/usr/lib"

cargo = ["cargo", "build", "--locked", "-Z", "build-std=std,panic_abort"]
# SDK setup must precede ring's C build. Repeating this is incremental.
subprocess.run(cargo + ["-p", "esp-idf-sys"], env=env, check=True)
if not gcc:
    gcc = sorted(tools.glob("tools/riscv32-esp-elf/*/riscv32-esp-elf/bin"))
    if gcc:
        env["PATH"] = str(gcc[-1]) + os.pathsep + env["PATH"]
args = ["--bin", binary]
if binary == "echo":
    args += ["--features", "echo"]
subprocess.run(cargo + args, env=env, check=True)
