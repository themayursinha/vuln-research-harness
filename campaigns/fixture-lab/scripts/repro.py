#!/usr/bin/env python3
"""Reproduction script for the synthetic path-join fixture."""
import os
import subprocess
import sys

SNAPSHOT = os.environ["VRH_SNAPSHOT"]
MARKER = "LAB-VULN-MARKER"
APP = os.path.join(SNAPSHOT, "app.py")

proc = subprocess.run(
    [sys.executable, APP, "../secret.txt"],
    capture_output=True,
    text=True,
    env=os.environ,
)
if "SYNTHETIC-SECRET" in proc.stdout:
    print(MARKER)
