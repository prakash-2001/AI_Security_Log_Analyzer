"""
LogParser — parse Apache/HTTPD access logs, SSH syslog lines, and generic
ISO-8601 timestamped lines into a unified list of structured log dicts.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Dict, List, Optional

from utils.helpers import safe_int


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------
_APACHE_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
)

_SSH_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+'
    r'(?P<event>Failed password|Accepted publickey|Accepted password|Invalid user)'
    r'(?:\sfor\s+(?P<user>\S+))?\s+from\s+(?P<ip>\d[\d.]+)\s+port\s+(?P<port>\d+)'
)

_GENERIC_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})[^\d]*'
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

# Apache combined-log date format
_APACHE_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_apache_ts(ts: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts, _APACHE_TS_FMT)
    except ValueError:
        return None


def _parse_syslog_ts(month: str, day: str, time_str: str) -> Optional[datetime]:
    try:
        year = datetime.utcnow().year
        return datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


class LogParser:
    """Parse raw log text into a list of normalised log-entry dicts."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw: str) -> List[Dict]:
        entries: List[Dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            entry = (
                self._try_apache(line)
                or self._try_ssh(line)
                or self._try_generic(line)
                or {"raw": line, "format": "unknown"}
            )
            entries.append(entry)
        return entries

    # ------------------------------------------------------------------
    # Format-specific parsers
    # ------------------------------------------------------------------

    def _try_apache(self, line: str) -> Optional[Dict]:
        m = _APACHE_RE.search(line)
        if not m:
            return None
        status = safe_int(m.group("status"))
        ts_obj = _parse_apache_ts(m.group("ts"))
        return {
            "format":     "apache",
            "timestamp":  m.group("ts"),
            "ts_obj":     ts_obj,
            "hour":       ts_obj.hour if ts_obj else None,
            "source_ip":  m.group("ip"),
            "method":     m.group("method"),
            "path":       m.group("path"),
            "action":     f"{m.group('method')} {m.group('path')}",
            "status_code": status,
            "status":     "failed" if status >= 400 else "success",
            "bytes":      safe_int(m.group("bytes")),
            "raw":        line,
        }

    def _try_ssh(self, line: str) -> Optional[Dict]:
        m = _SSH_RE.search(line)
        if not m:
            return None
        event   = m.group("event")
        ts_obj  = _parse_syslog_ts(m.group("month"), m.group("day"), m.group("time"))
        success = "Accepted" in event
        return {
            "format":     "ssh",
            "timestamp":  f"{m.group('month')} {m.group('day')} {m.group('time')}",
            "ts_obj":     ts_obj,
            "hour":       ts_obj.hour if ts_obj else None,
            "source_ip":  m.group("ip"),
            "user":       m.group("user") or "unknown",
            "port":       safe_int(m.group("port")),
            "action":     event,
            "event_type": "ssh_auth",
            "status":     "success" if success else "failed",
            "raw":        line,
        }

    def _try_generic(self, line: str) -> Optional[Dict]:
        m = _GENERIC_RE.search(line)
        if not m:
            return None
        return {
            "format":    "generic",
            "timestamp": m.group("ts"),
            "ts_obj":    None,
            "hour":      None,
            "source_ip": m.group("ip"),
            "action":    line,
            "status":    "failed" if re.search(r"\b(error|fail|denied|blocked)\b", line, re.I) else "unknown",
            "raw":       line,
        }
