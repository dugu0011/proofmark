"""Static lint: no undefined names anywhere in the package.

This is the guard for the bug that shipped a broken CLI — a name used but never
defined (a closure whose definition edit silently no-op'd). ast.parse and the
unit tests missed it because the crash only happens deep in a live run; pyflakes
catches it statically in milliseconds.
"""
import pathlib
import subprocess
import sys


def test_no_undefined_names():
    root = pathlib.Path(__file__).resolve().parent.parent / "proofmark"
    proc = subprocess.run(
        [sys.executable, "-m", "pyflakes", str(root)],
        capture_output=True, text=True,
    )
    # Only fail on undefined names (F821) — unused imports etc. are not our concern here.
    undefined = [line for line in proc.stdout.splitlines() if "undefined name" in line]
    assert not undefined, "undefined names found:\n" + "\n".join(undefined)
