"""Reconstruct MOSS's ASCII histograms into numbers.

MOSS renders real interval distributions as ASCII art that nobody reads
(RESEARCH §3.8). The drawing is a lossless-enough encoding of a numeric
distribution: each row is a count level, each column an interval bucket, and
the label row underneath carries the scale.

Nothing here is documented by the vendor, so the reconstructor reports how
confident it is: ``full`` when the recovered bucket counts sum to the stated
event total, ``partial`` when they do not, ``failed`` when the drawing could
not be read at all. Analyzers must degrade findings accordingly.
"""

from __future__ import annotations

import re

from mosslib.model import Histogram, HistogramBucket

SEQUENCE_RE = re.compile(
    r"^\s*sequence\s+(?P<keys>(?:\[[^\]]*\]\s*)+):\s*(?P<what>.*?)\s*$", re.IGNORECASE
)
NO_RECOIL_RE = re.compile(r"^\s*Mouse down moves\s*\(\s*no recoil\s*\)\s*$", re.IGNORECASE)
EVENTS_RE = re.compile(r"(?P<n>\d+)\s+events")
ROW_RE = re.compile(r"^(?P<pad>\s*)(?P<value>\d+)?\s*\|(?P<body>.*)$")
AXIS_RE = re.compile(r"^\s*[-+ ]{4,}.*$")
LABELS_RE = re.compile(r"^[\s\d]+$")
UNIT_RE = re.compile(r">\s*(?P<max>\d+)\s*(?P<unit>ms|px|us|s)\b", re.IGNORECASE)
KEY_RE = re.compile(r"\[([^\]]*)\]")

#: Characters that count as a plotted mark. MOSS uses ``X``; accept anything
#: non-blank so a version that switched to ``#`` still reconstructs.
_BLANK = " \t"


def is_histogram_body(line: str) -> bool:
    """True for a line that belongs to a histogram drawing rather than the log."""
    if not line.strip():
        return True
    if "|" in line and ROW_RE.match(line):
        return True
    if EVENTS_RE.search(line) and "^" in line:
        return True
    if AXIS_RE.match(line) and set(line.strip()) <= set("-+ >0123456789msuxp."):
        return True
    return bool(LABELS_RE.match(line))


def _label_positions(line: str) -> list[tuple[int, float]]:
    """Column -> value pairs from a tick-label row, using each number's first column."""
    return [(m.start(), float(m.group())) for m in re.finditer(r"\d+", line)]


def _column_to_value(column: int, labels: list[tuple[int, float]]) -> float | None:
    """Piecewise-linear map from a drawing column to the axis value it sits over."""
    if len(labels) < 2:
        return None
    for (c0, v0), (c1, v1) in zip(labels, labels[1:], strict=False):
        if c0 <= column <= c1:
            if c1 == c0:
                return v0
            return v0 + (v1 - v0) * (column - c0) / (c1 - c0)
    (c0, v0), (c1, v1) = labels[0], labels[1]
    step = (v1 - v0) / max(c1 - c0, 1)
    if column < labels[0][0]:
        return v0 + step * (column - c0)
    (cn1, vn1), (cn, vn) = labels[-2], labels[-1]
    step = (vn - vn1) / max(cn - cn1, 1)
    return vn + step * (column - cn)


def reconstruct(block: list[str], *, line_number: int = 0) -> Histogram:
    """Turn one histogram block (title line first) into a :class:`Histogram`."""
    title = block[0] if block else ""
    keys: list[str] = []
    kind = "unknown"
    label = title.strip()

    seq = SEQUENCE_RE.match(title)
    if seq:
        keys = [k.strip() for k in KEY_RE.findall(seq.group("keys"))]
        kind = "interval"
        label = f"sequence {' '.join('[' + k + ']' for k in keys)}"
    elif NO_RECOIL_RE.match(title):
        kind = "no_recoil"
        label = "Mouse down moves (no recoil)"

    hist = Histogram(kind=kind, label=label, keys=keys, line=line_number)

    unit = "ms"
    total_events: int | None = None
    rows: list[tuple[int | None, str]] = []
    label_rows: list[list[tuple[int, float]]] = []

    for line in block[1:]:
        if total_events is None:
            m = EVENTS_RE.search(line)
            if m and "|" not in line:
                total_events = int(m.group("n"))
                continue
        um = UNIT_RE.search(line)
        if um:
            unit = um.group("unit").lower()
        row = ROW_RE.match(line)
        if row:
            level = int(row.group("value")) if row.group("value") else None
            # Column offsets must stay absolute to line up with the label row.
            body = " " * row.start("body") + row.group("body")
            rows.append((level, body if body.strip() else " " * row.start("body")))
            continue
        if LABELS_RE.match(line) and line.strip():
            label_rows.append(_label_positions(line))

    hist.unit = unit
    hist.total_events = total_events

    labels = max(label_rows, key=len) if label_rows else []
    if not rows or len(labels) < 2:
        hist.reconstruction = "failed"
        return hist

    # Rows are drawn top-down with descending counts. Rows whose y-label MOSS
    # omitted inherit the descending sequence rather than being discarded.
    resolved: list[int] = []
    known = [(i, v) for i, (v, _) in enumerate(rows) if v is not None]
    inferred = False
    for i, (value, _) in enumerate(rows):
        if value is not None:
            resolved.append(value)
            continue
        inferred = True
        after = next((v for j, v in known if j > i), None)
        before = next((v for j, v in reversed(known) if j < i), None)
        if after is not None:
            resolved.append(after + (min(j for j, _ in known if j > i) - i))
        elif before is not None:
            resolved.append(max(before - (i - max(j for j, _ in known if j < i)), 0))
        else:
            resolved.append(0)

    column_counts: dict[int, int] = {}
    for value, body in zip(resolved, [b for _, b in rows], strict=True):
        for col, char in enumerate(body):
            if char not in _BLANK:
                column_counts[col] = max(column_counts.get(col, 0), value)

    if not column_counts:
        hist.reconstruction = "failed"
        return hist

    step: float | None = None
    if len(labels) >= 2:
        spans = [
            (labels[i + 1][1] - labels[i][1]) for i in range(len(labels) - 1)
            if labels[i + 1][1] > labels[i][1]
        ]
        step = min(spans) if spans else None

    buckets: dict[float, int] = {}
    for col, count in sorted(column_counts.items()):
        mapped = _column_to_value(col, labels)
        if mapped is None:
            continue
        # Snap onto the label grid so two columns of the same bar merge.
        bucket = float(round(mapped / step) * step) if step else float(mapped)
        buckets[bucket] = max(buckets.get(bucket, 0), count)

    hist.buckets = [
        HistogramBucket(lower=lo, upper=(lo + step) if step else None, count=count)
        for lo, count in sorted(buckets.items())
    ]

    # "full" means the recovered counts account for every event the drawing
    # claims, with no row heights inferred. Anything less is "partial", and
    # findings built on it are downgraded.
    recovered = sum(b.count for b in hist.buckets)
    counts_disagree = total_events is not None and recovered != total_events
    hist.reconstruction = "partial" if (counts_disagree or inferred) else "full"
    return hist


def recovered_events(hist: Histogram) -> int:
    return sum(b.count for b in hist.buckets)
