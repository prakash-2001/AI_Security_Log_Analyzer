"""
Shared helper functions used across the project.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def extract_ip(text: str) -> Optional[str]:
    """Return first IPv4 address found in *text*, or None."""
    match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
    return match.group(1) if match else None


def score_to_severity(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 25:
        return "LOW"
    return "INFO"


def truncate(text: str, max_len: int = 120) -> str:
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def flatten_logs_for_prompt(anomalies: List[Dict]) -> str:
    lines = []
    for a in anomalies:
        lines.append(
            f"- [{a.get('type','unknown').upper()}] "
            f"IP={a.get('ip','N/A')} | "
            f"Score={a.get('score', 0)}/100 | "
            f"{a.get('description','')}"
        )
    return "\n".join(lines)
