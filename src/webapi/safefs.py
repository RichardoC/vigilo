"""Symlink-safe access to files inside a run workspace.

A run's workspace (``{data_dir}/repo/.vigilo/{session}/``) is writable by the AI
agents (prompt-injectable). Anything the API serves from it must therefore never
follow a symlink out of it (e.g. ``report.md -> /proc/self/environ``). Every path
component below ``data_dir`` is opened with ``O_NOFOLLOW`` relative to its parent
directory fd, and the final file must be a regular file.
"""
from __future__ import annotations

import os
import stat
from typing import BinaryIO

_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


def _valid(parts: tuple[str, ...]) -> bool:
    return all(p and p not in (".", "..") and "/" not in p and "\0" not in p for p in parts)


def open_nofollow(base: str, *parts: str) -> int | None:
    """Open ``base/parts...`` read-only without following any symlink below ``base``.

    Returns a file descriptor for a regular file, or None when the path is missing,
    contains a symlink, or is not a regular file. ``base`` itself is trusted
    (it is resolved with realpath)."""
    if not parts or not _valid(parts):
        return None
    try:
        dfd = os.open(os.path.realpath(base), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return None
    try:
        for comp in parts[:-1]:
            try:
                nfd = os.open(comp, _DIR_FLAGS, dir_fd=dfd)
            except OSError:
                return None
            os.close(dfd)
            dfd = nfd
        try:
            fd = os.open(parts[-1], _FILE_FLAGS, dir_fd=dfd)
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                return None
        except OSError:
            os.close(fd)
            return None
        return fd
    finally:
        os.close(dfd)


def open_file(base: str, *parts: str) -> BinaryIO | None:
    fd = open_nofollow(base, *parts)
    if fd is None:
        return None
    os.set_blocking(fd, True)
    return os.fdopen(fd, "rb")


def is_safe_file(base: str, *parts: str) -> bool:
    fd = open_nofollow(base, *parts)
    if fd is None:
        return False
    os.close(fd)
    return True


def read_bytes(base: str, *parts: str, max_bytes: int | None = None) -> bytes | None:
    fh = open_file(base, *parts)
    if fh is None:
        return None
    with fh:
        return fh.read() if max_bytes is None else fh.read(max_bytes)


def list_regular(base: str, *parts: str) -> list[str]:
    """Names of regular, non-symlink files directly inside the directory ``base/parts``."""
    if parts and not _valid(parts):
        return []
    try:
        dfd = os.open(os.path.realpath(base), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return []
    try:
        for comp in parts:
            try:
                nfd = os.open(comp, _DIR_FLAGS, dir_fd=dfd)
            except OSError:
                return []
            os.close(dfd)
            dfd = nfd
        out = []
        for name in sorted(os.listdir(dfd)):
            try:
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                out.append(name)
        return out
    finally:
        os.close(dfd)
