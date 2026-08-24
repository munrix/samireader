"""Trying to identify MOSS's ``Global log CRC``.

The algorithm behind the footer line is undocumented (RESEARCH §3.9), which is
listed as a risk in PLAN §7. Per-file verification already covers most
tampering, so nothing depends on this — but an archive is a free experiment,
so the tool runs the candidate algorithms on every log it sees and reports a
match if one lands.

Two consequences, both wanted:

* if a candidate matches, whole-log verification becomes available immediately
  and every report says which algorithm proved it;
* if none matches, the report says the footer is **unverified**, rather than
  implying the log was checked when it was not.

Adding a candidate is a three-line change. That is the point.
"""

from __future__ import annotations

import hashlib
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass

FOOTER_PREFIX = "Global log CRC:"


@dataclass(frozen=True)
class Candidate:
    """One guess at how MOSS derives the footer value."""

    name: str
    description: str


def _digests(data: bytes) -> Iterator[tuple[str, str]]:
    yield "sha256", hashlib.sha256(data).hexdigest()
    yield "sha1", hashlib.sha1(data).hexdigest()
    yield "md5", hashlib.md5(data).hexdigest()
    yield "sha512", hashlib.sha512(data).hexdigest()
    yield "crc32", format(zlib.crc32(data) & 0xFFFFFFFF, "08x")


def _bodies(text: str, file_crcs: list[str]) -> Iterator[tuple[str, bytes]]:
    """Plausible inputs to the footer digest, most likely first."""
    lines = text.splitlines()
    body_lines = [ln for ln in lines if not ln.lstrip().startswith(FOOTER_PREFIX)]
    body = "\n".join(body_lines)

    variants: list[tuple[str, str]] = [
        ("log body, LF, no trailing newline", body),
        ("log body, LF, trailing newline", body + "\n"),
        ("log body, CRLF, no trailing newline", body.replace("\n", "\r\n")),
        ("log body, CRLF, trailing newline", body.replace("\n", "\r\n") + "\r\n"),
        ("log body with the footer label but no value", body + f"\n{FOOTER_PREFIX} "),
        ("concatenated per-file Zip CRC values", "".join(file_crcs)),
        ("concatenated per-file Zip CRC values, newline separated", "\n".join(file_crcs)),
    ]
    for label, variant in variants:
        for encoding in ("utf-8", "cp1252"):
            try:
                yield f"{label} ({encoding})", variant.encode(encoding)
            except UnicodeEncodeError:
                continue


def identify(text: str, expected: str, file_crcs: list[str] | None = None) -> tuple[str, str] | None:
    """Return (algorithm, input description) if a candidate reproduces ``expected``."""
    if not expected:
        return None
    target = expected.strip().lower()
    for description, data in _bodies(text, file_crcs or []):
        for algorithm, digest in _digests(data):
            if digest == target:
                return algorithm, description
    return None


#: Exposed so a researcher can enumerate what has already been ruled out.
def candidate_count(text: str, file_crcs: list[str] | None = None) -> int:
    return sum(1 for _ in _bodies(text, file_crcs or [])) * 5


def verify(text: str, expected: str, file_crcs: list[str] | None = None) -> tuple[bool, str]:
    """Human-readable outcome for the report."""
    match = identify(text, expected, file_crcs)
    if match:
        algorithm, description = match
        return True, f"{algorithm} of {description}"
    return False, (
        f"no match among {candidate_count(text, file_crcs)} candidate algorithm/input "
        "combinations"
    )


_DIGEST_FUNCTIONS: dict[str, Callable[[bytes], str]] = {
    "sha256": lambda data: hashlib.sha256(data).hexdigest(),
    "sha1": lambda data: hashlib.sha1(data).hexdigest(),
    "md5": lambda data: hashlib.md5(data).hexdigest(),
    "sha512": lambda data: hashlib.sha512(data).hexdigest(),
    "crc32": lambda data: format(zlib.crc32(data) & 0xFFFFFFFF, "08x"),
}
