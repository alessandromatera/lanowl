"""Run every tests/test_*.py, each in its own process, and report PASS/FAIL per module.

    python tests/run_all.py            # all modules
    python tests/run_all.py remote     # only modules whose name contains "remote"

Each module's full output is kept in .test-logs/<module>.log. Exit status 1 if any failed.
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    want = [a for a in sys.argv[1:] if not a.startswith("-")]
    mods = sorted(os.path.basename(p)[:-3] for p in glob.glob(os.path.join(ROOT, "tests", "test_*.py")))
    if want:
        mods = [m for m in mods if any(w in m for w in want)]
    logs = os.path.join(ROOT, ".test-logs")
    os.makedirs(logs, exist_ok=True)
    failed = []
    for m in mods:
        t0 = time.time()
        with open(os.path.join(logs, m + ".log"), "w") as out:
            rc = subprocess.call([sys.executable, "-m", f"tests.{m}"], cwd=ROOT, stdout=out,
                                 stderr=subprocess.STDOUT, timeout=600)
        print(f"  {m:24s} {'PASS' if rc == 0 else 'FAIL'}  {time.time() - t0:5.1f}s")
        if rc:
            failed.append(m)
    print(f"{len(mods) - len(failed)}/{len(mods)} passed" + (f"; failed: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
