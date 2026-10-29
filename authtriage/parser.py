"""Raw sshd auth lines to structured Events (syslog and ISO/journald timestamps).

Non-sshd and unrecognised lines are skipped silently: an auth log is a shared
file, so unrelated noise is normal rather than an error. See README for format.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}

_SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<tod>\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$")
_ISO_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<rest>.*)$")
_TAG = re.compile(r"^(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9._/-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$")

# Ordered: first match wins. Each yields an event kind plus named groups.
_MESSAGES = tuple((kind, re.compile(pattern)) for kind, pattern in (
    ("failed_password",
     r"^Failed (?:password|publickey|none|keyboard-interactive(?:/pam)?) for "
     r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
    ("invalid_user", r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?"),
    ("accepted",
     r"^Accepted (?:password|publickey|keyboard-interactive(?:/pam)?|none) for "
     r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
    ("pam_failure", r"^pam_unix\(sshd:auth\): authentication failure;.*?rhost=(?P<ip>\S+)"
     r"(?:\s+user=(?P<user>\S+))?\s*$"),
    ("preauth_disconnect", r"^(?:Connection closed by|Disconnected from)\s+"
     r"(?:(?:authenticating|invalid)\s+user\s+(?P<user>\S+)\s+)?"
     r"(?P<ip>\S+) port (?P<port>\d+).*\[preauth\]"),
))


@dataclass(frozen=True)
class Event:
    ts: datetime          # naive, normalised to UTC when the line carried an offset
    kind: str
    ip: Optional[str]
    user: Optional[str]
    port: Optional[int]
    invalid_user: bool
    host: str
    pid: Optional[int]
    line_no: int
    raw: str


def _parse_timestamp(line: str, year: int, last_month: Optional[int]):
    """(datetime, remainder, month), or None if the line carries no timestamp."""
    match = _ISO_TS.match(line)
    if match:
        ts = datetime.fromisoformat(match.group("ts").replace("Z", "+00:00"))
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts, match.group("rest"), ts.month

    match = _SYSLOG_TS.match(line)
    month = MONTHS.get(match.group("mon")) if match else None
    if month is None:
        return None
    # Syslog omits the year. A month going backwards means the log crossed Jan 1.
    year += 1 if last_month is not None and month < last_month else 0
    hour, minute, second = (int(part) for part in match.group("tod").split(":"))
    return (datetime(year, month, int(match.group("day")), hour, minute, second),
            match.group("rest"), month)


def parse_lines(lines: Iterable[str], year: Optional[int] = None,
                process: str = "sshd") -> Iterator[Event]:
    """Yield an Event for every recognised sshd auth line, in file order."""
    year = year or datetime.now().year
    last_month: Optional[int] = None

    for line_no, raw in enumerate(lines, 1):
        raw = raw.rstrip("\n")
        if not raw.strip():
            continue
        parsed = _parse_timestamp(raw, year, last_month)
        if parsed is None:
            continue
        ts, rest, month = parsed
        if last_month is not None and month < last_month:
            year += 1
        last_month = month

        tag = _TAG.match(rest)
        if not tag or not tag.group("proc").startswith(process):
            continue
        message = tag.group("msg")

        for kind, pattern in _MESSAGES:
            found = pattern.match(message)
            if not found:
                continue
            groups = found.groupdict()
            port = groups.get("port")
            yield Event(
                ts=ts, kind=kind, ip=groups.get("ip"), user=groups.get("user") or None,
                port=int(port) if port else None,
                invalid_user=bool(groups.get("invalid")) or kind == "invalid_user",
                host=tag.group("host"),
                pid=int(tag.group("pid")) if tag.group("pid") else None,
                line_no=line_no,
                raw=raw,
            )
            break


def parse_file(path: str, year: Optional[int] = None) -> list[Event]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return list(parse_lines(handle, year=year))
