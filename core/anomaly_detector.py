"""
AnomalyDetector — rule-based threat detection engine.

Rules implemented:
  1. Brute Force         — repeated failed auth attempts from same IP
  2. Data Exfiltration   — unusually high volume / large byte transfers
  3. Privilege Escalation — access to /admin paths
  4. Path Traversal      — directory traversal patterns
  5. Off-Hours Access    — admin/sensitive access between midnight and 06:00
  6. Credential Stuffing — many different usernames tried from same IP (SSH)
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Dict, List

from utils.helpers import score_to_severity


# Patterns indicating path-traversal attempts
_TRAVERSAL_RE = re.compile(r"(\.\./|%2e%2e|%252e|/etc/passwd|/etc/shadow|wp-admin)", re.I)


class AnomalyDetector:
    def __init__(self, threshold: int = 55):
        self.threshold = threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, logs: List[Dict]) -> List[Dict]:
        """Return anomaly dicts for all rules that fire above *threshold*."""
        anomalies: List[Dict] = []
        anomalies.extend(self._brute_force(logs))
        anomalies.extend(self._data_exfiltration(logs))
        anomalies.extend(self._privilege_escalation(logs))
        anomalies.extend(self._path_traversal(logs))
        anomalies.extend(self._off_hours_admin(logs))
        anomalies.extend(self._credential_stuffing(logs))

        # De-duplicate by (type, ip), keeping highest score
        seen: Dict[tuple, Dict] = {}
        for a in anomalies:
            key = (a["type"], a.get("ip", ""))
            if key not in seen or a["score"] > seen[key]["score"]:
                seen[key] = a

        filtered = [a for a in seen.values() if a["score"] >= self.threshold]
        # Enrich with severity label
        for a in filtered:
            a["severity"] = score_to_severity(a["score"])
        return sorted(filtered, key=lambda x: x["score"], reverse=True)

    # ------------------------------------------------------------------
    # Rule implementations
    # ------------------------------------------------------------------

    def _brute_force(self, logs: List[Dict]) -> List[Dict]:
        """Rule 1: ≥5 failed login/auth attempts from the same IP."""
        failures: Dict[str, List[Dict]] = defaultdict(list)
        for log in logs:
            if log.get("status") == "failed" and log.get("source_ip"):
                failures[log["source_ip"]].append(log)

        results = []
        for ip, failed_logs in failures.items():
            count = len(failed_logs)
            if count >= 5:
                score = min(40 + count * 6, 100)
                results.append({
                    "type":        "brute_force",
                    "ip":          ip,
                    "score":       score,
                    "description": f"{count} failed auth attempts from {ip}",
                    "evidence":    failed_logs[:5],
                    "count":       count,
                })
        return results

    def _data_exfiltration(self, logs: List[Dict]) -> List[Dict]:
        """Rule 2: Very high request count OR very large total bytes from one IP."""
        ip_logs: Dict[str, List[Dict]] = defaultdict(list)
        for log in logs:
            if log.get("source_ip"):
                ip_logs[log["source_ip"]].append(log)

        results = []
        for ip, ip_log_list in ip_logs.items():
            count      = len(ip_log_list)
            total_bytes = sum(l.get("bytes", 0) for l in ip_log_list)
            score = 0
            reasons = []

            if count >= 50:
                score += min(count // 5, 50)
                reasons.append(f"{count} requests")
            if total_bytes >= 100_000:
                score += min(total_bytes // 50_000, 40)
                reasons.append(f"{total_bytes:,} bytes transferred")

            if score >= 30:
                results.append({
                    "type":        "data_exfiltration",
                    "ip":          ip,
                    "score":       min(score, 100),
                    "description": f"Suspicious volume from {ip}: {', '.join(reasons)}",
                    "evidence":    ip_log_list[:5],
                    "count":       count,
                    "total_bytes": total_bytes,
                })
        return results

    def _privilege_escalation(self, logs: List[Dict]) -> List[Dict]:
        """Rule 3: Access to /admin or similar paths."""
        admin_logs: Dict[str, List[Dict]] = defaultdict(list)
        for log in logs:
            action = log.get("action", "") or log.get("path", "")
            if re.search(r"\b(admin|superuser|root|sudo|escalat)\b", action, re.I):
                ip = log.get("source_ip", "unknown")
                admin_logs[ip].append(log)

        results = []
        for ip, a_logs in admin_logs.items():
            hour   = a_logs[0].get("hour")
            score  = 70 + (15 if hour is not None and (hour < 6 or hour >= 22) else 0)
            score  = min(score, 100)
            results.append({
                "type":        "privilege_escalation",
                "ip":          ip,
                "score":       score,
                "description": f"Admin/privileged resource access from {ip} ({len(a_logs)} events)",
                "evidence":    a_logs[:5],
                "count":       len(a_logs),
            })
        return results

    def _path_traversal(self, logs: List[Dict]) -> List[Dict]:
        """Rule 4: Directory traversal / LFI patterns."""
        traversal_logs: Dict[str, List[Dict]] = defaultdict(list)
        for log in logs:
            raw = log.get("raw", "") + log.get("action", "") + log.get("path", "")
            if _TRAVERSAL_RE.search(raw):
                ip = log.get("source_ip", "unknown")
                traversal_logs[ip].append(log)

        results = []
        for ip, t_logs in traversal_logs.items():
            results.append({
                "type":        "path_traversal",
                "ip":          ip,
                "score":       min(65 + len(t_logs) * 5, 100),
                "description": f"Path traversal/LFI attempt from {ip} ({len(t_logs)} patterns)",
                "evidence":    t_logs[:5],
                "count":       len(t_logs),
            })
        return results

    def _off_hours_admin(self, logs: List[Dict]) -> List[Dict]:
        """Rule 5: Privileged access between midnight and 06:00."""
        results = []
        for log in logs:
            hour   = log.get("hour")
            action = log.get("action", "") or ""
            if hour is not None and hour < 6 and re.search(r"\badmin\b", action, re.I):
                ip = log.get("source_ip", "unknown")
                results.append({
                    "type":        "privilege_escalation",
                    "ip":          ip,
                    "score":       88,
                    "description": f"Admin access at {hour:02d}:00 from {ip} (off-hours)",
                    "evidence":    [log],
                    "count":       1,
                })
        return results

    def _credential_stuffing(self, logs: List[Dict]) -> List[Dict]:
        """Rule 6: Many distinct usernames tried via SSH from same IP."""
        ip_users: Dict[str, set] = defaultdict(set)
        for log in logs:
            if log.get("format") == "ssh" and log.get("status") == "failed":
                ip   = log.get("source_ip", "")
                user = log.get("user", "")
                if ip and user:
                    ip_users[ip].add(user)

        results = []
        for ip, users in ip_users.items():
            if len(users) >= 3:
                score = min(55 + len(users) * 8, 100)
                results.append({
                    "type":        "credential_stuffing",
                    "ip":          ip,
                    "score":       score,
                    "description": f"Credential stuffing: {len(users)} distinct usernames tried from {ip}",
                    "evidence":    [],
                    "count":       len(users),
                })
        return results
