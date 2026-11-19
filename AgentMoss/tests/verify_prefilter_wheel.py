"""Run outside the source tree against an independently installed wheel.

Example:
  PYTHONPATH=/tmp/agentmoss-wheel-installed python tests/verify_prefilter_wheel.py \
    --install-root /tmp/agentmoss-wheel-installed --compile-lib /path/libhs.so \
    --runtime-lib /path/libhs_runtime.so --backend hyperscan --expect-runtime-only
"""

import argparse
import json
from pathlib import Path
import re
import tempfile
import time

import agent_moss
from agent_moss.engine.prefilter_build import build_package
from agent_moss.engine.prefilter_contract import RuleSpec
from agent_moss.engine.prefilter_native import NativeLibrary
from agent_moss.engine.prefilter_reload import PackageManager
from agent_moss.engine.prefilter_storage import PackageBusy


def _wait(manager, previous=None):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        identity = manager.status()["active_package"]
        if identity is not None and identity != previous:
            return identity
        time.sleep(.01)
    raise AssertionError(f"package did not activate: {manager.status()}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--compile-lib", required=True)
    parser.add_argument("--runtime-lib", required=True)
    parser.add_argument("--backend", choices=("hyperscan", "ultrascan"), required=True)
    parser.add_argument("--expect-runtime-only", action="store_true")
    args = parser.parse_args()

    installed_source = Path(agent_moss.__file__).resolve()
    if not installed_source.is_relative_to(args.install_root.resolve()):
        raise AssertionError(f"import came from source checkout: {installed_source}")
    compile_info = NativeLibrary(args.compile_lib, backend=args.backend).info()
    runtime_info = NativeLibrary(args.runtime_lib, backend=args.backend).info()
    if args.expect_runtime_only and runtime_info["compiler_available"]:
        raise AssertionError("runtime library unexpectedly exposes compiler symbols")
    if compile_info["version_numeric"] != runtime_info["version_numeric"]:
        raise AssertionError("compile and runtime native versions differ")

    old_rules = (RuleSpec(r"curl\s+https://", re.I),)
    new_rules = (RuleSpec(r"wget\s+https://", re.I),)
    with tempfile.TemporaryDirectory() as directory:
        entry = Path(directory) / "prefilter.hsdb"
        build_package(old_rules, entry, library_path=args.compile_lib, backend=args.backend)
        manager = PackageManager(str(entry), args.runtime_lib, backend=args.backend, poll_interval=.01)
        manager.start()
        try:
            first = _wait(manager)
            old_binding = manager.bind(old_rules)
            assert old_binding.candidates("curl https://") == {0}
            deadline = time.monotonic() + 5
            while True:
                try:
                    build_package(new_rules, entry, library_path=args.compile_lib, backend=args.backend)
                    break
                except PackageBusy:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.01)
            second = _wait(manager, first)
            assert manager.bind(new_rules).candidates("wget https://") == {0}
            assert old_binding.candidates("curl https://") == {0}
            print(json.dumps({
                "installed_source": str(installed_source),
                "backend": args.backend,
                "native_version": runtime_info["version_numeric"],
                "runtime_compiler_available": runtime_info["compiler_available"],
                "first_package": first,
                "second_package": second,
                "pid": manager.status()["pid"],
                "hot_update": "passed",
            }, sort_keys=True))
        finally:
            manager.stop()


if __name__ == "__main__":
    main()
