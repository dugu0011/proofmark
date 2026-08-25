"""Applying a unified diff, so a proposed fix can be *verified* before it is shown.

A patch that does not apply is worse than no patch — it wastes the reader's time
and undermines trust in every other finding. So a proposed fix is checked the
same way a finding is: it must actually work. This applies a single-file unified
diff to the current file content in memory; if any context line does not match,
it refuses with the reason, and the fix is not recorded.

Deliberately small: it handles the ordinary unified-diff a model produces
(one file, @@ hunks). It is a validator, not a full patch program.
"""
from __future__ import annotations

import re

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchError(ValueError):
    """The diff could not be applied to the given content."""


def apply_unified_diff(original: str, diff: str) -> str:
    """Return `original` with `diff` applied, or raise PatchError."""
    src = original.splitlines()
    out: list[str] = []
    cursor = 0  # index into src consumed so far (0-based)

    lines = diff.splitlines()
    i = 0
    saw_hunk = False
    while i < len(lines):
        line = lines[i]
        if line.startswith(("--- ", "+++ ", "diff ", "index ")):
            i += 1
            continue
        m = _HUNK.match(line)
        if not m:
            i += 1
            continue
        saw_hunk = True
        start = int(m.group(1)) - 1  # 0-based start in the original
        if start < 0:
            start = 0
        # carry over unchanged lines before this hunk
        if start < cursor:
            raise PatchError("hunks are out of order or overlap")
        out.extend(src[cursor:start])
        cursor = start
        i += 1
        # apply the hunk body
        while i < len(lines) and not _HUNK.match(lines[i]) and not lines[i].startswith(("--- ", "+++ ")):
            body = lines[i]
            if body == "":
                # a blank line in the diff is context for a blank source line
                body = " "
            tag, text = body[0], body[1:]
            if tag == " ":
                if cursor >= len(src) or src[cursor] != text:
                    raise PatchError(f"context mismatch at source line {cursor + 1}")
                out.append(src[cursor])
                cursor += 1
            elif tag == "-":
                if cursor >= len(src) or src[cursor] != text:
                    raise PatchError(f"cannot remove line {cursor + 1}: it does not match")
                cursor += 1
            elif tag == "+":
                out.append(text)
            else:
                raise PatchError(f"unexpected diff line: {body!r}")
            i += 1

    if not saw_hunk:
        raise PatchError("no @@ hunks found — is this a unified diff?")
    out.extend(src[cursor:])
    result = "\n".join(out)
    if original.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result
