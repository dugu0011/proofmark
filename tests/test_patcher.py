"""The diff validator. A proposed fix is only shown if it actually applies, so
these pin exactly that: a good patch applies, a bad one is refused."""
import pytest
from proofmark.patcher import PatchError, apply_unified_diff

ORIGINAL = """import sqlite3

def user(uid):
    q = "SELECT * FROM users WHERE id = '%s'" % uid
    return q
"""


def test_a_valid_patch_applies():
    diff = """@@ -3,3 +3,3 @@
 def user(uid):
-    q = "SELECT * FROM users WHERE id = '%s'" % uid
+    q = ("SELECT * FROM users WHERE id = ?", (uid,))
     return q
"""
    out = apply_unified_diff(ORIGINAL, diff)
    assert "WHERE id = ?" in out
    assert "'%s'" not in out
    assert out.endswith("\n")


def test_a_patch_whose_context_does_not_match_is_refused():
    diff = """@@ -3,3 +3,3 @@
 def user(uid):
-    q = "THIS LINE IS NOT IN THE FILE"
+    q = "safe"
     return q
"""
    with pytest.raises(PatchError):
        apply_unified_diff(ORIGINAL, diff)


def test_pure_addition_applies():
    diff = """@@ -1,1 +1,2 @@
 import sqlite3
+import re
"""
    out = apply_unified_diff(ORIGINAL, diff)
    assert "import re" in out


def test_text_that_is_not_a_diff_is_refused():
    with pytest.raises(PatchError):
        apply_unified_diff(ORIGINAL, "just fix the sql injection please")
