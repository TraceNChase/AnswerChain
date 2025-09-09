# SPDX-License-Identifier: MIT
# Atomic persistence helpers for AnswerChain
from __future__ import annotations
from pathlib import Path
import json, os, tempfile, io, typing as t

__all__ = [
    "ensure_dir",
    "atomic_write_bytes",
    "atomic_write_text",
    "atomic_write_json",
]

def ensure_dir(d: Path) -> None:
    """
    Create directory `d` (and parents) if missing.
    Idempotent.
    """
    d.mkdir(parents=True, exist_ok=True)

def _atomic_replace(tmp_path: Path, final_path: Path) -> None:
    """
    Replace final_path with tmp_path atomically on the same filesystem.
    """
    os.replace(str(tmp_path), str(final_path))  # atomic on same FS

def atomic_write_bytes(path: Path, data: bytes) -> None:
    """
    Crash-safe write of bytes to `path`.
    """
    path = path.resolve()
    ensure_dir(path.parent)
    with tempfile.NamedTemporaryFile(
        dir=str(path.parent), delete=False
    ) as tf:
        tmp = Path(tf.name)
        with io.BufferedWriter(tf) as buf:
            buf.write(data)
            buf.flush()
            os.fsync(tf.fileno())
    _atomic_replace(tmp, path)

def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    atomic_write_bytes(path, text.encode(encoding))

def atomic_write_json(
    path: Path,
    obj: t.Any,
    *,
    indent: int = 2,
    sort_keys: bool = True,
    ensure_ascii: bool = False,
) -> None:
    payload = json.dumps(obj, indent=indent, sort_keys=sort_keys, ensure_ascii=ensure_ascii) + "\n"
    atomic_write_text(path, payload)
