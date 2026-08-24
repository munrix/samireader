"""Minimal JPEG structure reader — dimensions and integrity, no decoding.

Deliberately does not decode pixels. Decoding attacker-supplied images pulls in
a large native attack surface for a result the P0 rules do not need: frame
dimensions, truncation and the ``0xFFD8``/``0xFFD9`` envelope are enough to
catch a monitor swap mid-session and a corrupt or truncated capture.
"""

from __future__ import annotations

from dataclasses import dataclass

SOI = b"\xff\xd8"
EOI = b"\xff\xd9"
#: Start-of-frame markers. C4/C8/CC are DHT/JPG/DAC, not frames.
_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
_STANDALONE = {0xD8, 0xD9, 0x01, *range(0xD0, 0xD8)}


@dataclass
class JpegInfo:
    width: int | None = None
    height: int | None = None
    size: int = 0
    valid_soi: bool = False
    has_eoi: bool = False
    truncated: bool = False
    progressive: bool = False
    error: str | None = None

    @property
    def dimensions(self) -> tuple[int, int] | None:
        if self.width and self.height:
            return self.width, self.height
        return None

    @property
    def megapixels(self) -> float | None:
        if self.width and self.height:
            return self.width * self.height / 1_000_000
        return None


def inspect(data: bytes) -> JpegInfo:
    """Read a JPEG's frame header. Never raises on malformed input."""
    info = JpegInfo(size=len(data))
    info.valid_soi = data[:2] == SOI
    info.has_eoi = data[-2:] == EOI
    if not info.valid_soi:
        info.error = "missing JPEG SOI marker"
        return info

    pos = 2
    end = len(data)
    while pos < end - 1:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        pos += 2
        if marker in (0xFF, 0x00) or marker in _STANDALONE:
            continue
        if pos + 2 > end:
            info.truncated = True
            info.error = "segment length runs past end of file"
            break
        length = int.from_bytes(data[pos : pos + 2], "big")
        if length < 2 or pos + length > end:
            info.truncated = True
            info.error = "segment length runs past end of file"
            break
        if marker in _SOF:
            if length < 7:
                info.error = "truncated start-of-frame segment"
                break
            info.progressive = marker in (0xC2, 0xC6, 0xCA, 0xCE)
            info.height = int.from_bytes(data[pos + 3 : pos + 5], "big")
            info.width = int.from_bytes(data[pos + 5 : pos + 7], "big")
            break
        if marker == 0xDA:  # start of scan; entropy data follows, stop scanning
            break
        pos += length

    if info.width is None and info.error is None:
        info.error = "no start-of-frame segment found"
    if not info.has_eoi:
        info.truncated = True
    return info
