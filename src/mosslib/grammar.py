"""The MOSS log grammar, as regular expressions.

Reverse-engineered from five Rainbow Six archives written by MOSS 6.6.9.0
(RESEARCH §3) and from the vendor's published log-analysis page. It is not an
official specification, so every pattern here is written to be *tolerant*:
optional decorations stay optional, whitespace is flexible, and anything that
does not match is preserved as an unknown line rather than dropped.

Bump ``GRAMMAR_VERSION`` in :mod:`mosslib.version` whenever a change here
could alter a parse result.
"""

from __future__ import annotations

import re

TS = r"\d{4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}(?::\d{2})?"

# --- session header -------------------------------------------------------

HEADER_RE = re.compile(
    rf"^\s*SHAS2 mode started at\s+(?P<ts>{TS})\s+for\s+(?P<game>.+?)\s+on\s+(?P<arch>\S+)\s*$"
)
PING_RE = re.compile(r"^\s*ping:\s*(?P<ms>\d+)\s*ms\s*$", re.IGNORECASE)
UPDATE_RE = re.compile(r"^\s*update\s+(?P<value>\S+)\s*$")
DIRECTX_RE = re.compile(r"^\s*DirectX version is\s+(?P<value>.+?)\s*$")
OS_RE = re.compile(r"^\s*OS is\s+(?P<value>.+?)\s*$")
REAL_OS_RE = re.compile(r"^\s*Real OS\s+(?P<value>.+?)\s*$")

# --- hardware inventory ---------------------------------------------------

PCI_RE = re.compile(
    r"^\s*PCI:\s*(?P<desc>.+?)(?:\s*\((?P<vid>0x[0-9A-Fa-f]+)-(?P<did>0x[0-9A-Fa-f]+)\))?\s*$"
)
MEMORY_RE = re.compile(r"^\s*memory:\s*(?P<mb>\d+)\s*MB\s*$", re.IGNORECASE)
VERSION_RE = re.compile(r"^\s*version:\s*MOSS\s+(?P<version>[\d,.\s]+?)\s*$", re.IGNORECASE)
PHYSICAL_RE = re.compile(r"^\s*Physical:\s*(?P<value>.+?)\s*$")
SIGN_ID_RE = re.compile(r"^\s*Sign ID1:\s*(?P<value>\S+)\s*$")
USER_RE = re.compile(r"^\s*User:\s*(?P<user>[^@]*?)(?:@(?P<host>.+?))?\s*$")
DRIVE_RE = re.compile(r"^\s*Drive:\s*(?P<desc>.*?)\s*serial:\s*(?P<serial>.*?)\s*$")
NET_RE = re.compile(r"^\s*Net:\s*(?P<lan>\S+)(?:\s+Public:\s*(?P<wan>\S+))?\s*$")
VIDEO_RE = re.compile(r"^\s*Video:\s*(?P<desc>.+?)\s*driver\s*:\s*(?P<driver>.*?)\s*$")
MONITOR_RE = re.compile(r"^\s*Monitor:\s*(?P<desc>.*?)\s*serial:\s*(?P<serial>.*?)\s*$")
USB_RE = re.compile(
    r"^\s*Usb:\s*(?P<desc>.+?)"
    r"(?:\s*\((?P<serial>[^()]*?)\))?"
    r"(?:\s*\((?P<vid>0x[0-9A-Fa-f]+)-(?P<did>0x[0-9A-Fa-f]+)\))?\s*$"
)
PROCESSOR_RE = re.compile(
    r"^\s*processor BIOS details\s+(?P<mhz>\d+)\s*MHz\s*by\s*"
    r"(?P<mult>[\d.]+)\s*\*\s*(?P<base>[\d.]+)\.\s*(?P<name>.+?)\s*$"
)
MONITOR_STARTED_RE = re.compile(rf"^\s*Monitor Started at\s+(?P<ts>{TS})\s*$")
DEFENDER_RE = re.compile(r"^\s*Windows Defender:\s*(?P<value>.+?)\s*$")
STEAM_ID_RE = re.compile(r"^\s*SteamId:\s*(?P<value>.*?)\s*$")

# --- processes ------------------------------------------------------------

PROCESS_RE = re.compile(
    r"^\s*(?P<star>\*)?SHAS2:\s+(?P<sha>[0-9a-fA-F]{32,64})\s+"
    r"(?:Author:\s*(?P<author>.*?)\s+)?process:\s*(?P<path>.+?)\s*$"
)
GAME_DETECTED_RE = re.compile(r"^\s*Game Detected\s*$", re.IGNORECASE)

# --- file capture ---------------------------------------------------------

FILECHECK_START_RE = re.compile(
    rf"^\s*FileCheck start for\s+(?P<path>.+?)\s+at\s+(?P<ts>{TS})\s*:?\s*$"
)
FILECHECK_END_RE = re.compile(
    rf"^\s*FileCheck end for\s+(?P<path>.+?)\s+at\s+(?P<ts>{TS})\s*:?\s*$"
)
SEARCH_FILES_RE = re.compile(r"^\s*Search for files\s*$", re.IGNORECASE)

#: Every record that carries a ``Zip CRC:`` — screenshots and captured files
#: alike. Deliberately generic: the decorations before ``file:`` differ between
#: MOSS versions, and losing a hash because a counter moved is unacceptable.
FILE_RECORD_RE = re.compile(
    r"^(?P<prefix>.*?)\bfile:\s*(?P<file>.+?)\s*-\s*Zip CRC:\s*(?P<crc>[0-9a-fA-F]{8,})\s*$"
)
CAPTURED_PREFIX_RE = re.compile(r"^\s*captured:\s*(?P<path>.*?)\s*$")
AT_TIME_RE = re.compile(rf"\bat\s+(?P<ts>{TS})")
MONITOR_INDEX_RE = re.compile(r"\(\s*Mon\s+(?P<index>\d+)\s*\)", re.IGNORECASE)
EACH_RE = re.compile(r"\bEach\s+(?P<seconds>\d+)\b", re.IGNORECASE)
BACKEND_RE = re.compile(r"^\s*(?P<backend>[A-Za-z][A-Za-z0-9_]*)\b")
API_RE = re.compile(r"\b(?P<api>D3D\d+|DX\d+|GL|Vulkan|GDI)\s*\(", re.IGNORECASE)
COUNTER_RE = re.compile(r"\((?P<n>\d+)\)")

# --- process statistics ---------------------------------------------------

STATS_HEADER_RE = re.compile(
    r"^\s*Processes statistics\s*(?:ping:\s*(?P<ping>\d+))?\s*$", re.IGNORECASE
)
STATS_COLUMNS_RE = re.compile(r"^\s*PID\s+Running Time\s+Kernel Time\s+User Time\s+Name\s*$")
STATS_ROW_RE = re.compile(
    r"^\s*(?P<pid>\d+)\s*[\t ]\s*(?P<running>[\d:]+)\s*[\t ]\s*(?P<kernel>[\d:]+)"
    r"\s*[\t ]\s*(?P<user>[\d:]+)\s*[\t ]\s*(?P<name>.+?)\s*$"
)

# --- footer ---------------------------------------------------------------

GLOBAL_CRC_RE = re.compile(r"^\s*Global log CRC:\s*(?P<crc>[0-9a-fA-F]+)\s*$", re.IGNORECASE)
