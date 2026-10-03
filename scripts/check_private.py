"""Fail if any file in the tree matches a private denylist of identifiers.

The denylist is a list of case-insensitive regexes, one per line (# starts a comment). It
lives outside the repository on purpose: kept inside, it would publish the very things it
guards. Point at it with LANOWL_DENYLIST (default ~/.config/lanowl/house-denylist.txt).

    python scripts/check_private.py            # exit 1 and list the hits
    python scripts/check_private.py --quiet    # counts per file only
    python scripts/check_private.py DIR        # check another tree instead of this repo
"""
from __future__ import annotations

import os
import re
import sys

SKIP_DIRS = {".git", ".venv", ".test-logs", "dist", "build", "__pycache__", ".mypy_cache", ".pytest_cache"}
DEFAULT = os.path.expanduser("~/.config/lanowl/house-denylist.txt")


def load(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        lines = [ln.strip() for ln in f]
    return [re.compile(ln, re.IGNORECASE) for ln in lines if ln and not ln.startswith("#")]


def files(root: str):
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for n in names:
            yield os.path.join(d, n)


def main() -> int:
    quiet = "--quiet" in sys.argv
    dirs = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = os.environ.get("LANOWL_DENYLIST", DEFAULT)
    if not os.path.exists(path):
        print(f"no denylist at {path}: nothing to check against", file=sys.stderr)
        return 2
    rules = load(path)
    root = os.path.abspath(dirs[0]) if dirs else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    total = 0
    for p in sorted(files(root)):
        try:
            with open(p, encoding="utf-8") as f:
                text = f.read()
        except (UnicodeDecodeError, OSError):
            continue
        hits = [(i, rx.pattern) for i, line in enumerate(text.splitlines(), 1)
                for rx in rules if rx.search(line)]
        if not hits:
            continue
        total += len(hits)
        rel = os.path.relpath(p, root)
        if quiet:
            print(f"{len(hits):5d}  {rel}")
        else:
            for i, pat in hits:
                print(f"{rel}:{i}: /{pat}/")
    print(f"{total} hit(s)" if total else "clean", file=sys.stderr)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
