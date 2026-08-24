"""The appeal packet — everything the accused needs to contest a finding.

DECISIONS D1 requires this from P0: if the output feeds disciplinary
proceedings, the person it is used against must be able to check the work.
A report they cannot inspect is not evidence, it is an assertion.

The packet is a directory, not a format: the dossier as they would see it, the
same findings as data, the exact rule pack version that produced them, and the
custody records for their archive. Nothing here is generated specially for the
appeal — it is the same analysis, which is the point.
"""

from __future__ import annotations

import json
from pathlib import Path

from sami.dossier import Dossier
from sami.ingest import CustodyLog
from sami.redact import Redactor
from sami.report.html import render_dossier, write_report
from sami.version import RULESET_VERSION, __version__

COVER = """SAMIREADER APPEAL PACKET
========================

Evidence ID (SHA-256 of the archive as submitted):
  {evidence_id}

Archive filename : {filename}
Subject          : {subject}
Reviewed with    : samireader {version} (ruleset {ruleset})
Rule pack        : {rules}
Produced         : {generated}
Review priority  : {band} — {meaning}

WHAT IS IN THIS PACKET
----------------------
  dossier.html    The full report, with every finding, the evidence behind it, the
                  arithmetic that produced it, and the innocent explanation for the
                  same evidence stated alongside the suspicious one.
  findings.json   The same findings as data, so they can be checked mechanically.
  rules.json      The exact thresholds and lists used. A finding that depends on a
                  threshold can be re-checked against it.
  session.json    Everything the tool read out of the archive, including every log
                  line it did not recognise.
  custody.jsonl   Every action taken against this archive, by whom and when.
                  (Absent if the review was run without a custody log.)

HOW TO CONTEST A FINDING
------------------------
Each finding names the rule that produced it (for example
"integrity.file-hash-mismatch") and lists the evidence it rests on: log line
numbers, file names, and the computed values. To contest one:

  1. Check the arithmetic. Every Tier 1 finding is a computation over the
     archive you submitted. Recompute it — the report states exactly what was
     compared with what.
  2. Read the benign explanation printed with the finding. If it describes what
     happened, say so, and say what evidence supports it.
  3. Check the threshold in rules.json. Findings that depend on one say so.
  4. Where a finding is marked "moderate" or "low" confidence, or "partial
     reconstruction", the tool is stating that its own measurement is uncertain.

WHAT THIS TOOL DOES NOT CLAIM
-----------------------------
{limitations}

The review priority above is a queue position — which archives an admin opens
first. It is not a score, not a probability, and not a finding about a person.
No output of this tool is a verdict. A human decides, on the evidence, and this
packet is that evidence.
"""


def write_packet(
    dossier: Dossier,
    directory: str | Path,
    *,
    custody: CustodyLog | None = None,
    redacted: bool = False,
    salt: str | None = None,
) -> Path:
    """Write the appeal packet for one dossier. Returns the directory."""
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)

    packet_dossier = Redactor(salt=salt).dossier(dossier) if redacted and salt else (
        Redactor().dossier(dossier) if redacted else dossier
    )

    write_report(
        target / "dossier.html",
        render_dossier(packet_dossier, embed_images="flagged", redacted=redacted),
    )
    payload = packet_dossier.to_json()
    (target / "findings.json").write_text(
        json.dumps(payload["findings"], indent=2), encoding="utf-8"
    )
    (target / "session.json").write_text(
        json.dumps(packet_dossier.session.to_json(), indent=2), encoding="utf-8"
    )
    (target / "rules.json").write_text(
        json.dumps(dossier.rules.data, indent=2), encoding="utf-8"
    )

    if custody is not None:
        records = [
            record
            for record in custody.read()
            if record.get("evidence_id") == dossier.scan.evidence_id
        ]
        if records:
            (target / "custody.jsonl").write_text(
                "\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n",
                encoding="utf-8",
            )

    band, meaning = dossier.priority
    (target / "READ-ME-FIRST.txt").write_text(
        COVER.format(
            evidence_id=dossier.scan.evidence_id,
            filename=packet_dossier.session.archive.filename,
            subject=packet_dossier.subject,
            version=__version__,
            ruleset=RULESET_VERSION,
            rules=dossier.rules.describe(),
            generated=dossier.generated_at.isoformat(),
            band=band,
            meaning=meaning,
            limitations="\n".join(f"  · {line}" for line in payload["limitations"]),
        ),
        encoding="utf-8",
    )
    return target
