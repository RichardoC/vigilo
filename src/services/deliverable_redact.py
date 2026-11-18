"""Final redaction pass over a run's deliverables.

Audit logs are redacted as they are written, but agent-written deliverables (evidence
write-ups quoting ``curl -H 'Cookie: ...'``, the final report, manifests) are not.
After the report stage this rewrites every text file under ``deliverables/`` with the
registered secrets masked (:func:`src.audit.redact.redact`).

The deliverables directory is writable by prompt-injectable agents, so the walk never
follows a symlink (every directory is opened with ``O_NOFOLLOW`` relative to its
parent), only regular files are touched, binaries are skipped, and the rewrite goes
through a temporary file renamed over the original (so a hard-link or symlink swap
cannot redirect the write).
"""
from __future__ import annotations

import logging
import os
import stat
from typing import Any

from src.audit.redact import redact

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 64 * 1024 * 1024
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


def _is_binary(data: bytes) -> bool:
    return b"\0" in data[:8192]


def _rewrite(dfd: int, name: str, stats: dict[str, Any], rel: str) -> None:
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=dfd)
    except OSError:
        stats["skipped"] += 1
        return
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
            stats["skipped"] += 1
            return
        with os.fdopen(os.dup(fd), "rb") as fh:
            data = fh.read()
    finally:
        os.close(fd)
    if _is_binary(data):
        stats["skipped"] += 1
        return
    text = data.decode("utf-8", errors="surrogateescape")
    new = redact(text)
    stats["scanned"] += 1
    if new == text:
        return
    tmp = f".{name}.vigilo-redact.{os.getpid()}"
    try:
        tfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                      stat.S_IMODE(st.st_mode) or 0o644, dir_fd=dfd)
        with os.fdopen(tfd, "wb") as out:
            out.write(new.encode("utf-8", errors="surrogateescape"))
        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        stats["redacted"] += 1
        stats["files"].append(rel)
    except OSError as exc:
        logger.warning("could not redact %s: %s", rel, exc)
        stats["errors"] += 1
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass


def _walk(dfd: int, rel: str, stats: dict[str, Any]) -> None:
    for name in sorted(os.listdir(dfd)):
        if name.endswith(f".vigilo-redact.{os.getpid()}"):
            continue
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except OSError:
            continue
        child = f"{rel}/{name}" if rel else name
        if stat.S_ISLNK(st.st_mode):
            stats["skipped"] += 1
        elif stat.S_ISDIR(st.st_mode):
            try:
                sub = os.open(name, _DIR_FLAGS, dir_fd=dfd)
            except OSError:
                continue
            try:
                _walk(sub, child, stats)
            finally:
                os.close(sub)
        elif stat.S_ISREG(st.st_mode):
            _rewrite(dfd, name, stats, child)


def redact_tree(base: str, *parts: str) -> dict[str, Any]:
    """Redact every text file under ``base/parts...`` in place. ``base`` is trusted
    (realpath-resolved); each component of ``parts`` is opened without following
    symlinks. Returns ``{"scanned", "redacted", "skipped", "errors", "files"}``."""
    stats: dict[str, Any] = {"scanned": 0, "redacted": 0, "skipped": 0, "errors": 0, "files": []}
    try:
        dfd = os.open(os.path.realpath(base), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return stats
    try:
        for comp in parts:
            try:
                nfd = os.open(comp, _DIR_FLAGS, dir_fd=dfd)
            except OSError:
                return stats  # missing, or a symlink: leave it alone
            os.close(dfd)
            dfd = nfd
        _walk(dfd, "", stats)
    finally:
        os.close(dfd)
    return stats
