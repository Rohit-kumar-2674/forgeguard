"""Bounded, deterministic file access within the selected repository."""

from __future__ import annotations

import os
import stat
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
MAX_FILE_BYTES = 1_000_000


def repository_files(root: Path) -> tuple[Path, ...]:
    def failed(error: OSError) -> None:
        raise error

    files = []
    for directory, children, names in os.walk(root, followlinks=False, onerror=failed):
        folder = Path(directory)
        children[:] = sorted(
            name for name in children if name not in SKIP_DIRS and not (folder / name).is_symlink()
        )
        for name in sorted(names):
            path = folder / name
            if stat.S_ISREG(path.lstat().st_mode):
                files.append(path)
    return tuple(files)


def read_text(path: Path) -> str | None:
    """Skip binary/oversized files; never read more than the limit plus one byte."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if path.is_symlink():
        return None
    with os.fdopen(os.open(path, flags), "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
            return None
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES or b"\x00" in data:
        return None
    return data.decode("utf-8", errors="replace")
