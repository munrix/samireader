"""Hashing helpers. One place, so the report and the verifier can never disagree."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import IO

CHUNK = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_stream(stream: IO[bytes], limit: int | None = None) -> tuple[str, int]:
    """SHA-256 a stream without holding it in memory. Returns (digest, bytes read).

    ``limit`` guards against decompression bombs: reading stops once it is
    exceeded, and the caller can detect that from the returned size.
    """
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(CHUNK)
        if not chunk:
            break
        total += len(chunk)
        digest.update(chunk)
        if limit is not None and total > limit:
            break
    return digest.hexdigest(), total


def sha256_file(path: str | Path) -> str:
    with open(path, "rb") as fh:
        return sha256_stream(fh)[0]


def looks_like_sha256(value: str | None) -> bool:
    if not value or len(value) != 64:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)
