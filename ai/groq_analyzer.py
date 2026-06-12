"""
GroqAnalyzer — wraps the Groq API (Llama 3 / Mixtral) for intelligent
threat analysis.  Falls back gracefully when no API key is provided.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

from utils.helpers import flatten_logs_for_prompt


_SYSTEM_PROMPT = """\
You are an expert cybersecurity analyst specialising in log-based threat detection.
Analyse the provided anomalies and respond ONLY with valid JSON — no markdown fences.
"""

_USER_TEMPLATE = """\
The rule-based engine detected the following anomalies in server logs:

{anomaly_text}

Return a JSON object with exactly this schema:
{{
  "overall_risk": <integer 1-10>,
  "summary": "<one-sentence plain-English summary>",
  "threats": [
    {{
      "type": "<threat category>",
      "severity": <integer 1-10>,
      "ip": "<source IP or N/A>",
      "description": "<what happened>",
      "immediate_action": "<what to do right now>",
      "confidence": <integer 0-100>
    }}
  ],
  "recommendations": [
    "<prioritised remediation step 1>",
    "<prioritised remediation step 2>",
    "<prioritised remediation step 3>"
  ]
}}
"""


class GroqAnalyzer:
    """AI-powered threat analysis via the Groq API."""

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key
        self._client  = None
        self._available = False
        self._init_client()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init_client(self) -> None:
        if not self._api_key:
            # Try Streamlit secrets
            try:
                import streamlit as st
                self._api_key = st.secrets.get("GROQ_API_KEY", "")
            except Exception:
                pass

        if not self._api_key or self._api_key.startswith("your_"):
            self._available = False
            return

        try:
            from groq import Groq  # type: ignore
            self._client    = Groq(api_key=self._api_key)
            self._available = True
        except Exception:
            self._available = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        return self._available

    def analyze(self, anomalies: List[Dict]) -> Dict:
        """
        Call Groq and return a structured analysis dict.
        Falls back to a heuristic response if Groq is unavailable.
        """
        if not anomalies:
            return self._empty_response()

        if not self._available:
            return self._heuristic_response(anomalies)

        anomaly_text = flatten_logs_for_prompt(anomalies)
        prompt       = _USER_TEMPLATE.format(anomaly_text=anomaly_text)

        try:
            resp = self._client.chat.completions.create(
                model="llama3-70b-8192",
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                max_tokens=1500,
                temperature=0.15,
            )
            raw_text = resp.choices[0].message.content
            return self._parse_response(raw_text, anomalies)
        except Exception as exc:
            return self._heuristic_response(anomalies, error=str(exc))

    # ------------------------------------------------------------------
    # Response parsing / fallbacks
    # ------------------------------------------------------------------

    def _parse_response(self, text: str, anomalies: List[Dict]) -> Dict:
        # Strip markdown fences if model added them anyway
        text = re.sub(r"```(?:json)?", "", text).strip()
        try:
            data = json.loads(text)
            data["ai_powered"] = True
            return data
        except json.JSONDecodeError:
            # Try to extract first {...} block
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group())
                    data["ai_powered"] = True
                    return data
                except Exception:
                    pass
        return self._heuristic_response(anomalies, raw_text=text)

    def _heuristic_response(
        self,
        anomalies: List[Dict],
        error: str = "",
        raw_text: str = "",
    ) -> Dict:
        """Build a rule-only response when AI is unavailable."""
        threats = []
        for a in anomalies:
            score    = a.get("score", 50)
            severity = max(1, min(10, score // 10))
            threats.append({
                "type":             a.get("type", "unknown"),
                "severity":         severity,
                "ip":               a.get("ip", "N/A"),
                "description":      a.get("description", ""),
                "immediate_action": _default_action(a.get("type", "")),
                "confidence":       75,
            })

        overall = max((t["severity"] for t in threats), default=1)
        return {
            "overall_risk":    overall,
            "summary":         f"{len(threats)} threat(s) detected by rule engine. "
                               + ("AI analysis unavailable — add GROQ_API_KEY for deeper insights." if not raw_text else ""),
            "threats":         threats,
            "recommendations": [
                "Block flagged IPs at the firewall immediately.",
                "Enable multi-factor authentication on all privileged accounts.",
                "Review and rotate credentials for affected services.",
            ],
            "ai_powered":      False,
            "_error":          error,
            "_raw":            raw_text[:500] if raw_text else "",
        }

    @staticmethod
    def _empty_response() -> Dict:
        return {
            "overall_risk":    0,
            "summary":         "No anomalies detected. System appears clean.",
            "threats":         [],
            "recommendations": ["Continue monitoring logs regularly."],
            "ai_powered":      False,
        }


def _default_action(threat_type: str) -> str:
    actions = {
        "brute_force":          "Block source IP; enforce account lockout policy.",
        "data_exfiltration":    "Throttle / block IP; audit accessed data.",
        "privilege_escalation": "Revoke session; audit admin access controls.",
        "path_traversal":       "Block IP; patch web server configuration.",
        "credential_stuffing":  "Enable CAPTCHA / rate-limiting on auth endpoints.",
        "off_hours_access":     "Verify identity; suspend session pending review.",
    }
    return actions.get(threat_type, "Investigate and block if confirmed malicious.")
