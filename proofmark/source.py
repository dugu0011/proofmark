"""Getting a code target ready to test.

Two shapes: a local directory, or a git repository we shallow-clone. Either way
the result is a local root that the CLI then copies *into the sandbox* — the
agent reads and runs the code in the jail, never on the host.

Deliberately minimal on the host side: we do not read or execute anything here.
The risky part (running the code) happens inside the container, where it is
capped and isolated.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class SourceError(RuntimeError):
    pass


@dataclass
class Source:
    """A local root holding the code to test, plus how we got it."""

    root: Path
    kind: str            # "path" | "repo"
    label: str           # what to show the user
    _cleanup: Path | None = None  # a temp dir to remove when done

    def dispose(self) -> None:
        if self._cleanup and self._cleanup.exists():
            shutil.rmtree(self._cleanup, ignore_errors=True)


def prepare(target: str, kind: str) -> Source:
    if kind == "path":
        return _from_path(target)
    if kind == "repo":
        return _from_repo(target)
    raise SourceError(f"not a code target: {kind}")


def _from_path(target: str) -> Source:
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise SourceError(f"no such path: {target}")
    if root.is_file():
        # A single file is a valid, if small, target — treat its folder as root.
        return Source(root=root.parent, kind="path", label=str(root))
    return Source(root=root, kind="path", label=str(root))


def _from_repo(target: str) -> Source:
    url = _normalize_repo_url(target)
    tmp = Path(tempfile.mkdtemp(prefix="proofmark-src-"))
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, str(tmp)],
            check=True, capture_output=True, timeout=180,
        )
    except FileNotFoundError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        raise SourceError("git is not installed on the host") from exc
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp, ignore_errors=True)
        raise SourceError("cloning the repository timed out")
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        detail = (exc.stderr or b"").decode("utf-8", "replace").strip()[:300]
        raise SourceError(f"could not clone {url}: {detail or 'git failed'}")
    return Source(root=tmp, kind="repo", label=url, _cleanup=tmp)


def _normalize_repo_url(target: str) -> str:
    """Accept the shorthand forms people actually type."""
    if target.startswith(("http://", "https://", "git@", "ssh://")):
        return target
    if target.count("/") == 1 and " " not in target:  # "owner/repo"
        return f"https://github.com/{target}.git"
    return target
