#!/usr/bin/env python3
"""Synthetic lab target: weak path join under a public/ prefix (fixture only)."""
import os
import sys

def read_public(name: str) -> str:
    base = os.environ.get("VRH_SNAPSHOT", ".")
    path = os.path.join(base, "public", name)
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: app.py <public-name>", file=sys.stderr)
        raise SystemExit(2)
    print(read_public(sys.argv[1]))
