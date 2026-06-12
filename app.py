"""
app.py — AI Security Log Analyzer
Main Streamlit entry point.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from typing import Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from ai.groq_analyzer import GroqAnalyzer
from core.anomaly_detector import AnomalyDetector
from core.log_parser import LogParser
from core.model_evaluator import ModelEvaluator
from utils.constants import (
    DEFAULT_THRESHOLD,
    MAX_ANOMALIES_FOR_AI,
    SAMPLE_LOGS,
    SEVERITY_COLORS,
    THREAT_ICONS,
)
from utils.helpers import score_to_severity, truncate

# ─────────────────────────────────────────────
# Page config (must be first Streamlit call)
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="AI Security Log Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
# Custom CSS — dark glassmorphism theme
# ─────────────────────────────────────────────
st.markdown(
    """
<style>
/* ---------- Google Font ---------- */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* ---------- Root palette ---------- */
:root {
    --bg-primary:   #0d0f1a;
    --bg-card:      rgba(255,255,255,0.04);
    --bg-card-hover:rgba(255,255,255,0.07);
    --border:       rgba(255,255,255,0.08);
    --accent-blue:  #4f8ef7;
    --accent-cyan:  #00d2ff;
    --accent-green: #34d399;
    --accent-red:   #f87171;
    --accent-orange:#fb923c;
    --accent-yellow:#facc15;
    --text-primary: #f1f5f9;
    --text-muted:   #94a3b8;
}

/* ---------- App background ---------- */
.stApp {
    background: linear-gradient(135deg, #0d0f1a 0%, #111827 50%, #0d1520 100%);
    background-attachment: fixed;
}

/* ---------- Hide Streamlit chrome ---------- */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 1.5rem 2rem; }

/* ---------- Sidebar ---------- */
[data-testid="stSidebar"] {
    background: rgba(15, 17, 28, 0.95);
    border-right: 1px solid var(--border);
    backdrop-filter: blur(12px);
}
[data-testid="stSidebar"] .stSlider label,
[data-testid="stSidebar"] .stCheckbox label,
[data-testid="stSidebar"] p { color: var(--text-muted) !important; }

/* ---------- Cards ---------- */
.glass-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 0.8rem;
    backdrop-filter: blur(10px);
    transition: background 0.2s, transform 0.15s;
}
.glass-card:hover {
    background: var(--bg-card-hover);
    transform: translateY(-1px);
}
    box-shadow: 0 4px 24px rgba(0,0,0,0.3);
}

/* ═══════════════════════════════════════════
   METRIC BOXES — responsive auto-grid
═══════════════════════════════════════════ */
.metric-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 0.6rem;
    margin-bottom: 0.6rem;
}
.metric-box {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: clamp(0.6rem, 2vw, 1rem) clamp(0.6rem, 2vw, 1.2rem);
    text-align: center;
    transition: background 0.2s ease, transform 0.15s ease;
}
.metric-box:hover {
    background: var(--bg-card-hover);
    transform: translateY(-1px);
}
.metric-value {
    font-size: var(--text-2xl);
    font-weight: 700;
    color: var(--text-primary);
    line-height: 1.1;
}
.metric-label {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--text-muted);
    margin-top: 0.25rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}

/* ═══════════════════════════════════════════
   RESPONSIVE METRIC GRID OVERRIDES
   (Streamlit's st.columns don't adapt — use CSS)
═══════════════════════════════════════════ */
@media (max-width: 480px) {
    .metric-value { font-size: 1.4rem !important; }
    .metric-label { font-size: 0.62rem !important; }
    .metric-box   { padding: 0.5rem 0.4rem !important; }
    .glass-card   { border-radius: 10px !important; padding: 0.7rem 0.9rem !important; }
}

/* ═══════════════════════════════════════════
   SEVERITY BADGES
═══════════════════════════════════════════ */
.badge {
    display: inline-block;
    padding: 0.18rem 0.7rem;
    border-radius: 20px;
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.04em;
    white-space: nowrap;
}
.badge-CRITICAL { background: rgba(248,113,113,0.18); color: #f87171; border: 1px solid rgba(248,113,113,0.4); }
.badge-HIGH     { background: rgba(251,146,60,0.18);  color: #fb923c; border: 1px solid rgba(251,146,60,0.4); }
.badge-MEDIUM   { background: rgba(250,204,21,0.14);  color: #facc15; border: 1px solid rgba(250,204,21,0.35); }
.badge-LOW      { background: rgba(52,211,153,0.14);  color: #34d399; border: 1px solid rgba(52,211,153,0.35); }
.badge-INFO     { background: rgba(79,142,247,0.14);  color: #4f8ef7; border: 1px solid rgba(79,142,247,0.35); }

/* ═══════════════════════════════════════════
   SECTION TITLES
═══════════════════════════════════════════ */
.section-title {
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
}

/* ═══════════════════════════════════════════
   PAGE HEADER — fluid hero
═══════════════════════════════════════════ */
.app-header {
    display: flex;
    align-items: center;
    gap: clamp(0.5rem, 2vw, 1rem);
    margin-bottom: clamp(1rem, 3vw, 1.5rem);
    flex-wrap: wrap;
}
.app-header-icon  { font-size: clamp(1.8rem, 5vw, 2.8rem); line-height: 1; }
.app-header-title { font-size: var(--text-xl); font-weight: 700; color: #f1f5f9; letter-spacing: -0.02em; }
.app-header-sub   { font-size: var(--text-sm); color: #64748b; margin-top: 0.1rem; }

/* ═══════════════════════════════════════════
   GLOW BUTTON — touch friendly
═══════════════════════════════════════════ */
.stButton > button {
    background: linear-gradient(135deg, #4f8ef7, #00d2ff);
    color: #fff !important;
    border: none !important;
    border-radius: var(--radius-sm) !important;
    font-weight: 600 !important;
    font-size: var(--text-sm) !important;
    padding: clamp(0.5rem, 2vw, 0.65rem) clamp(1rem, 4vw, 1.6rem) !important;
    transition: box-shadow 0.2s, transform 0.15s !important;
    width: 100% !important;
    min-height: 44px;   /* WCAG touch target */
    cursor: pointer;
}
.stButton > button:hover {
    box-shadow: 0 0 22px rgba(79,142,247,0.55) !important;
    transform: translateY(-1px) !important;
}
.stButton > button:active { transform: scale(0.98) !important; }

/* ═══════════════════════════════════════════
   TABS — scrollable on mobile
═══════════════════════════════════════════ */
.stTabs [data-baseweb="tab-list"] {
    gap: 0.2rem;
    background: transparent;
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
    overflow-y: hidden;
    flex-wrap: nowrap;
    -webkit-overflow-scrolling: touch;
    scrollbar-width: none;
}
.stTabs [data-baseweb="tab-list"]::-webkit-scrollbar { display: none; }
.stTabs [data-baseweb="tab"] {
    background: transparent;
    color: var(--text-muted);
    border-radius: 8px 8px 0 0;
    font-size: clamp(0.72rem, 1.8vw, 0.85rem);
    padding: clamp(0.35rem, 1.5vw, 0.5rem) clamp(0.6rem, 2vw, 1rem);
    white-space: nowrap;
    flex-shrink: 0;
    min-height: 40px;
}
.stTabs [aria-selected="true"] {
    background: rgba(79,142,247,0.12) !important;
    color: #4f8ef7 !important;
    border-bottom: 2px solid #4f8ef7 !important;
}

/* ═══════════════════════════════════════════
   ALERTS
═══════════════════════════════════════════ */
.stAlert { border-radius: var(--radius-sm) !important; }

/* ═══════════════════════════════════════════
   TEXT AREA & FILE UPLOADER
═══════════════════════════════════════════ */
.stTextArea textarea {
    background: rgba(255,255,255,0.03) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-sm) !important;
    color: var(--text-primary) !important;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: clamp(0.7rem, 1.5vw, 0.8rem);
    resize: vertical;
}
[data-testid="stFileUploader"] {
    border: 1px dashed var(--border) !important;
    border-radius: var(--radius-md) !important;
    background: var(--bg-card) !important;
    transition: border-color 0.2s;
}
[data-testid="stFileUploader"]:hover { border-color: var(--accent-blue) !important; }

/* ═══════════════════════════════════════════
   DATAFRAME / TABLE
═══════════════════════════════════════════ */
[data-testid="stDataFrame"] {
    border-radius: var(--radius-md) !important;
    overflow: hidden;
}
[data-testid="stDataFrame"] table { font-size: clamp(0.68rem, 1.5vw, 0.82rem) !important; }

/* ═══════════════════════════════════════════
   SLIDER — mobile-friendly
═══════════════════════════════════════════ */
[data-testid="stSlider"] [role="slider"] {
    width: 20px !important;
    height: 20px !important;
}

/* ═══════════════════════════════════════════
   INPUT — larger tap targets
═══════════════════════════════════════════ */
.stTextInput input {
    background: rgba(255,255,255,0.04) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-sm) !important;
    color: var(--text-primary) !important;
    min-height: 42px;
    font-size: var(--text-sm) !important;
}
.stTextInput input:focus {
    border-color: var(--accent-blue) !important;
    box-shadow: 0 0 0 2px rgba(79,142,247,0.2) !important;
}

/* ═══════════════════════════════════════════
   CHECKBOX — larger tap target
═══════════════════════════════════════════ */
[data-testid="stCheckbox"] { min-height: 36px; }
[data-testid="stCheckbox"] label { cursor: pointer; }

/* ═══════════════════════════════════════════
   PLOTLY — transparent + responsive
═══════════════════════════════════════════ */
.js-plotly-plot .plotly { background: transparent !important; }
.js-plotly-plot         { border-radius: var(--radius-md); overflow: hidden; }

/* ═══════════════════════════════════════════
   SCROLLBAR — thin & styled
═══════════════════════════════════════════ */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.12); border-radius: 8px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.22); }
* { scrollbar-width: thin; scrollbar-color: rgba(255,255,255,0.12) transparent; }

/* ═══════════════════════════════════════════
   THREAT CARD RESPONSIVE — wrap flex items
═══════════════════════════════════════════ */
.threat-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.6rem 1.5rem;
}
.threat-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin-bottom: 0.5rem;
}

/* ═══════════════════════════════════════════
   RULE CARD GRID — responsive columns
═══════════════════════════════════════════ */
.rule-metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(80px, 1fr));
    gap: clamp(0.4rem, 1.5vw, 0.8rem);
}
.rule-bars-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(80px, 1fr));
    gap: 0.4rem;
    margin-top: 0.6rem;
}

/* ═══════════════════════════════════════════
   MOBILE-SPECIFIC OVERRIDES  (≤ 640px)
═══════════════════════════════════════════ */
@media (max-width: 640px) {
    .app-header-title { font-size: 1.2rem !important; }
    .app-header-sub   { font-size: 0.72rem !important; }
    .metric-value { font-size: 1.5rem !important; }
    .stTabs [data-baseweb="tab"] { font-size: 0.65rem !important; padding: 0.3rem 0.5rem !important; }
    .threat-header { flex-direction: column !important; }
    .threat-meta   { gap: 0.3rem 0.8rem !important; }
    .rule-metrics-grid { grid-template-columns: repeat(2, 1fr) !important; }
}

/* ═══════════════════════════════════════════
   TABLET OVERRIDES  (641px – 1024px)
═══════════════════════════════════════════ */
@media (min-width: 641px) and (max-width: 1024px) {
    .metric-value { font-size: 1.7rem !important; }
    .rule-metrics-grid { grid-template-columns: repeat(3, 1fr) !important; }
}

/* ═══════════════════════════════════════════
   DESKTOP  (> 1024px)
═══════════════════════════════════════════ */
@media (min-width: 1025px) {
    .rule-metrics-grid { grid-template-columns: repeat(5, 1fr) !important; }
}

/* ═══════════════════════════════════════════
   PRINT STYLES
═══════════════════════════════════════════ */
@media print {
    [data-testid="stSidebar"], .stButton { display: none !important; }
    .stApp { background: white !important; }
    .glass-card { border: 1px solid #e2e8f0 !important; background: #f8fafc !important; }
    .metric-value, .app-header-title { color: #0f172a !important; }
}
</style>
""",
    unsafe_allow_html=True,
)

# ─────────────────────────────────────────────
# Page header
# ─────────────────────────────────────────────
st.markdown(
    """
<div class="app-header">
  <div class="app-header-icon">🔒</div>
  <div>
    <div class="app-header-title">AI Security Log Analyzer</div>
    <div class="app-header-sub">Powered by Groq · Rule-Based Engine · Real-time Threat Intelligence</div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

# ─────────────────────────────────────────────
# Sidebar — settings
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        "<div style='font-size:1.1rem;font-weight:700;color:#f1f5f9;margin-bottom:1rem;'>⚙️ Settings</div>",
        unsafe_allow_html=True,
    )

    api_key = st.text_input(
        "Groq API Key (optional)",
        type="password",
        placeholder="gsk_...",
        help="Get a free key at console.groq.com. Without it, heuristic analysis is used.",
    )

    st.markdown("---")

    threshold = st.slider(
        "Anomaly sensitivity threshold",
        min_value=0,
        max_value=100,
        value=DEFAULT_THRESHOLD,
        help="Lower = more sensitive (more detections). Higher = fewer, higher-confidence alerts.",
    )

    st.markdown("---")

    use_sample = st.checkbox("Load sample logs", value=True)

    st.markdown("---")

    st.markdown(
        "<div class='section-title'>Detection Rules</div>",
        unsafe_allow_html=True,
    )
    for rule in [
        "🔨 Brute Force",
        "📤 Data Exfiltration",
        "⬆️ Privilege Escalation",
        "🗂️ Path Traversal",
        "🌙 Off-Hours Admin Access",
        "🔑 Credential Stuffing",
    ]:
        st.markdown(
            f"<span style='font-size:0.82rem;color:#64748b;'>✓ {rule}</span>",
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown(
        "<div style='font-size:0.72rem;color:#334155;text-align:center;'>v1.0 · Free to run · Deployed on Streamlit Cloud</div>",
        unsafe_allow_html=True,
    )

# ─────────────────────────────────────────────
# Log input area
# ─────────────────────────────────────────────
col_input, col_results = st.columns([1, 1], gap="large")

with col_input:
    st.markdown("<div class='section-title'>📤 Log Input</div>", unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "Upload a log file (.log, .txt)",
        type=["log", "txt"],
        label_visibility="collapsed",
    )

    if uploaded:
        log_text = uploaded.read().decode("utf-8", errors="replace")
        st.success(f"✅ Loaded **{uploaded.name}** ({len(log_text.splitlines())} lines)")
    elif use_sample:
        log_text = SAMPLE_LOGS
        st.info("📋 Using built-in sample logs. Uncheck 'Load sample logs' to paste your own.")
    else:
        log_text = st.text_area(
            "Paste raw logs",
            height=320,
            placeholder="Paste Apache / SSH / syslog entries here…",
            label_visibility="collapsed",
        )

    if log_text:
        lines = [l for l in log_text.splitlines() if l.strip()]
        st.markdown(
            f"<div class='glass-card' style='margin-top:0.6rem;'>"
            f"<span style='font-size:0.8rem;color:#64748b;'>📄 {len(lines)} log lines ready for analysis</span>"
            f"</div>",
            unsafe_allow_html=True,
        )

    analyze_btn = st.button("🚀 Analyze with AI", key="analyze_btn", use_container_width=True)


# ─────────────────────────────────────────────
# Analysis pipeline
# ─────────────────────────────────────────────
with col_results:
    st.markdown("<div class='section-title'>🔍 Analysis Output</div>", unsafe_allow_html=True)

    if not analyze_btn:
        st.markdown(
            """
<div class="glass-card" style="text-align:center;padding:3rem 1rem;">
  <div style="font-size:3rem;margin-bottom:0.8rem;">🛡️</div>
  <div style="font-size:1rem;font-weight:600;color:#f1f5f9;">Ready to analyze</div>
  <div style="font-size:0.82rem;color:#475569;margin-top:0.4rem;">
    Add logs on the left and click <strong>Analyze with AI</strong>
  </div>
</div>
""",
            unsafe_allow_html=True,
        )
    elif not log_text or not log_text.strip():
        st.warning("⚠️ No log data provided. Please paste logs or upload a file.")
    else:
        # ── Step 1: Parse ──────────────────────────────────────────────
        with st.spinner("🔄 Parsing logs…"):
            parser = LogParser()
            logs   = parser.parse(log_text)

        # ── Step 2: Detect ─────────────────────────────────────────────
        with st.spinner("🔎 Running detection rules…"):
            detector  = AnomalyDetector(threshold=threshold)
            anomalies = detector.detect(logs)

        # ── Step 3: AI analysis ────────────────────────────────────────
        with st.spinner("🤖 Calling Groq AI for threat intelligence…"):
            analyzer = GroqAnalyzer(api_key=api_key or None)
            ai_data  = analyzer.analyze(anomalies[:MAX_ANOMALIES_FOR_AI])

        # ── Display results ────────────────────────────────────────────
        ai_badge = "✨ AI-Powered" if ai_data.get("ai_powered") else "⚙️ Heuristic"
        sev_color = SEVERITY_COLORS.get(
            score_to_severity(ai_data.get("overall_risk", 0) * 10), "#4f8ef7"
        )
        st.markdown(
            f"""
<div class="glass-card" style="border-left:3px solid {sev_color};margin-bottom:1rem;">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;">
    <div>
      <span style="font-size:0.72rem;color:#64748b;font-weight:600;letter-spacing:.08em;text-transform:uppercase;">
        Overall Risk
      </span>
      <div style="font-size:1.6rem;font-weight:700;color:{sev_color};margin:.15rem 0;">
        {ai_data.get('overall_risk', '?')}/10
      </div>
      <div style="font-size:0.82rem;color:#94a3b8;">{ai_data.get('summary','')}</div>
    </div>
    <span style="font-size:0.72rem;font-weight:600;color:#64748b;">{ai_badge}</span>
  </div>
</div>
""",
            unsafe_allow_html=True,
        )

        # ── Model Evaluation ───────────────────────────────────────────
        evaluator = ModelEvaluator(logs=logs, anomalies=anomalies, threshold=threshold)
        eval_overall   = evaluator.overall()
        eval_per_rule  = evaluator.per_rule()
        eval_conf_bk   = evaluator.confidence_breakdown()
        eval_score_dist= evaluator.score_distribution()
        eval_radar     = evaluator.radar_data()

        # ── Tabs ───────────────────────────────────────────────────────
        tab_threats, tab_charts, tab_ai, tab_eval, tab_raw = st.tabs(
            ["🚨 Threats", "📊 Charts", "🤖 AI Insights", "📈 Model Evaluation", "📋 Raw Logs"]
        )

        # ── Tab 1: Threats ─────────────────────────────────────────────
        with tab_threats:
            if not anomalies:
                st.success("✅ No anomalies detected at the current threshold.")
            else:
                for a in anomalies:
                    icon     = THREAT_ICONS.get(a.get("type", "unknown"), "⚠️")
                    severity = a.get("severity", score_to_severity(a.get("score", 0)))
                    color    = SEVERITY_COLORS.get(severity, "#4f8ef7")
                    st.markdown(
                        f"""
<div class="glass-card" style="border-left:3px solid {color};">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
    <span style="font-weight:600;color:#f1f5f9;font-size:0.9rem;">{icon} {a.get('type','unknown').replace('_',' ').title()}</span>
    <span class="badge badge-{severity}">{severity}</span>
  </div>
  <div style="font-size:0.82rem;color:#94a3b8;margin-bottom:0.4rem;">{a.get('description','')}</div>
  <div style="display:flex;gap:1.5rem;">
    <span style="font-size:0.75rem;color:#475569;">🌐 IP: <strong style="color:#f1f5f9;">{a.get('ip','N/A')}</strong></span>
    <span style="font-size:0.75rem;color:#475569;">📊 Score: <strong style="color:{color};">{a.get('score',0)}/100</strong></span>
    <span style="font-size:0.75rem;color:#475569;">📝 Events: <strong style="color:#f1f5f9;">{a.get('count',1)}</strong></span>
  </div>
</div>
""",
                        unsafe_allow_html=True,
                    )

        # ── Tab 2: Charts ──────────────────────────────────────────────
        with tab_charts:
            if not anomalies:
                st.info("No anomalies to chart.")
            else:
                c1, c2 = st.columns(2)

                # Threat type distribution
                with c1:
                    types  = [a.get("type", "unknown").replace("_", " ").title() for a in anomalies]
                    counts = Counter(types)
                    fig_pie = go.Figure(
                        go.Pie(
                            labels=list(counts.keys()),
                            values=list(counts.values()),
                            hole=0.55,
                            marker=dict(colors=["#4f8ef7","#f87171","#fb923c","#facc15","#34d399","#a78bfa"]),
                            textinfo="label+percent",
                            textfont_size=11,
                        )
                    )
                    fig_pie.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#94a3b8",
                        showlegend=False,
                        margin=dict(t=10, b=10, l=10, r=10),
                        height=260,
                    )
                    st.markdown("<div class='section-title'>Threat Distribution</div>", unsafe_allow_html=True)
                    st.plotly_chart(fig_pie, use_container_width=True, config={"displayModeBar": False})

                # Score bar chart
                with c2:
                    df_scores = pd.DataFrame(
                        [
                            {
                                "label": f"{THREAT_ICONS.get(a.get('type','unknown'),'⚠️')} {a.get('ip','?')}",
                                "score": a.get("score", 0),
                                "severity": a.get("severity", "LOW"),
                            }
                            for a in anomalies
                        ]
                    ).sort_values("score", ascending=True).tail(10)

                    color_map = {"CRITICAL":"#f87171","HIGH":"#fb923c","MEDIUM":"#facc15","LOW":"#34d399","INFO":"#4f8ef7"}
                    bar_colors = [color_map.get(s, "#4f8ef7") for s in df_scores["severity"]]

                    fig_bar = go.Figure(
                        go.Bar(
                            x=df_scores["score"],
                            y=df_scores["label"],
                            orientation="h",
                            marker=dict(color=bar_colors, opacity=0.85),
                            text=df_scores["score"].astype(str),
                            textposition="outside",
                            textfont=dict(color="#94a3b8", size=10),
                        )
                    )
                    fig_bar.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#94a3b8",
                        xaxis=dict(range=[0, 110], gridcolor="rgba(255,255,255,0.05)"),
                        yaxis=dict(gridcolor="rgba(255,255,255,0)"),
                        margin=dict(t=10, b=10, l=10, r=40),
                        height=260,
                    )
                    st.markdown("<div class='section-title'>Anomaly Scores</div>", unsafe_allow_html=True)
                    st.plotly_chart(fig_bar, use_container_width=True, config={"displayModeBar": False})

                # Metrics row
                st.markdown("<hr style='border-color:rgba(255,255,255,0.06);margin:0.4rem 0;'>", unsafe_allow_html=True)
                m1, m2, m3, m4 = st.columns(4)
                with m1:
                    st.markdown(
                        f"<div class='metric-box'><div class='metric-value'>{len(logs)}</div>"
                        f"<div class='metric-label'>Log Lines</div></div>",
                        unsafe_allow_html=True,
                    )
                with m2:
                    st.markdown(
                        f"<div class='metric-box'><div class='metric-value' style='color:#f87171;'>{len(anomalies)}</div>"
                        f"<div class='metric-label'>Anomalies</div></div>",
                        unsafe_allow_html=True,
                    )
                with m3:
                    critical = len([a for a in anomalies if a.get("severity") in ("CRITICAL","HIGH")])
                    st.markdown(
                        f"<div class='metric-box'><div class='metric-value' style='color:#fb923c;'>{critical}</div>"
                        f"<div class='metric-label'>High+Critical</div></div>",
                        unsafe_allow_html=True,
                    )
                with m4:
                    unique_ips = len(set(a.get("ip") for a in anomalies if a.get("ip")))
                    st.markdown(
                        f"<div class='metric-box'><div class='metric-value' style='color:#facc15;'>{unique_ips}</div>"
                        f"<div class='metric-label'>Affected IPs</div></div>",
                        unsafe_allow_html=True,
                    )

        # ── Tab 3: AI Insights ─────────────────────────────────────────
        with tab_ai:
            ai_threats = ai_data.get("threats", [])
            recs       = ai_data.get("recommendations", [])

            if not ai_threats:
                st.info("No AI threat data. Ensure anomalies were detected.")
            else:
                st.markdown("<div class='section-title'>AI-Classified Threats</div>", unsafe_allow_html=True)
                for t in ai_threats:
                    sev      = t.get("severity", 5)
                    sev_name = score_to_severity(sev * 10)
                    color    = SEVERITY_COLORS.get(sev_name, "#4f8ef7")
                    icon     = THREAT_ICONS.get(t.get("type","unknown").lower().replace(" ","_"), "⚠️")
                    conf     = t.get("confidence", 75)
                    st.markdown(
                        f"""
<div class="glass-card" style="border-left:3px solid {color};">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem;">
    <span style="font-weight:600;color:#f1f5f9;">{icon} {t.get('type','').replace('_',' ').title()}</span>
    <div style="display:flex;gap:.5rem;align-items:center;">
      <span class="badge badge-{sev_name}">Severity {sev}/10</span>
      <span style="font-size:.7rem;color:#475569;">{conf}% confidence</span>
    </div>
  </div>
  <div style="font-size:.82rem;color:#94a3b8;margin-bottom:.5rem;">{t.get('description','')}</div>
  <div style="background:rgba(79,142,247,.07);border-radius:8px;padding:.5rem .8rem;">
    <span style="font-size:.72rem;color:#4f8ef7;font-weight:600;">⚡ IMMEDIATE ACTION: </span>
    <span style="font-size:.8rem;color:#cbd5e1;">{t.get('immediate_action','Review and investigate.')}</span>
  </div>
</div>
""",
                        unsafe_allow_html=True,
                    )

            if recs:
                st.markdown("<div class='section-title' style='margin-top:1rem;'>📌 Recommendations</div>", unsafe_allow_html=True)
                for i, rec in enumerate(recs, 1):
                    st.markdown(
                        f"<div class='glass-card' style='padding:.7rem 1rem;'>"
                        f"<span style='color:#4f8ef7;font-weight:700;margin-right:.5rem;'>{i}.</span>"
                        f"<span style='font-size:.82rem;color:#94a3b8;'>{rec}</span>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

            if not ai_data.get("ai_powered"):
                st.markdown(
                    "<div style='font-size:.75rem;color:#475569;text-align:center;margin-top:.5rem;'>"
                    "💡 Add your Groq API key in the sidebar for deeper AI-powered analysis."
                    "</div>",
                    unsafe_allow_html=True,
                )

        # ── Tab 4: Model Evaluation ────────────────────────────────────
        with tab_eval:
            ov = eval_overall
            grade_color = {
                "A+": "#34d399", "A": "#34d399", "B+": "#86efac",
                "B": "#facc15", "C+": "#fb923c", "C": "#fb923c", "D": "#f87171"
            }.get(ov["overall_grade"], "#4f8ef7")

            # ── Header metrics ──────────────────────────────────────────
            st.markdown("<div class='section-title'>🎯 Overall Model Performance</div>", unsafe_allow_html=True)
            hm1, hm2, hm3, hm4, hm5 = st.columns(5)
            with hm1:
                st.markdown(
                    f"<div class='metric-box'>"
                    f"<div class='metric-value' style='color:{grade_color};font-size:2.4rem;'>{ov['overall_grade']}</div>"
                    f"<div class='metric-label'>Model Grade</div></div>",
                    unsafe_allow_html=True,
                )
            with hm2:
                st.markdown(
                    f"<div class='metric-box'>"
                    f"<div class='metric-value' style='color:#4f8ef7;'>{ov['overall_conf']}%</div>"
                    f"<div class='metric-label'>Confidence</div></div>",
                    unsafe_allow_html=True,
                )
            with hm3:
                st.markdown(
                    f"<div class='metric-box'>"
                    f"<div class='metric-value' style='color:#34d399;'>{ov['avg_precision']}%</div>"
                    f"<div class='metric-label'>Avg Precision</div></div>",
                    unsafe_allow_html=True,
                )
            with hm4:
                st.markdown(
                    f"<div class='metric-box'>"
                    f"<div class='metric-value' style='color:#a78bfa;'>{ov['avg_recall']}%</div>"
                    f"<div class='metric-label'>Avg Recall</div></div>",
                    unsafe_allow_html=True,
                )
            with hm5:
                st.markdown(
                    f"<div class='metric-box'>"
                    f"<div class='metric-value' style='color:#facc15;'>{ov['avg_f1']}%</div>"
                    f"<div class='metric-label'>Avg F1 Score</div></div>",
                    unsafe_allow_html=True,
                )

            st.markdown("<br>", unsafe_allow_html=True)

            # ── Row 1: Gauge + Radar ─────────────────────────────────────
            gc1, gc2 = st.columns([1, 1])

            with gc1:
                st.markdown("<div class='section-title'>Overall Confidence Gauge</div>", unsafe_allow_html=True)
                conf_val = ov["overall_conf"]
                gauge_color = grade_color
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number+delta",
                    value=conf_val,
                    delta={"reference": 75, "valueformat": ".1f",
                           "increasing": {"color": "#34d399"}, "decreasing": {"color": "#f87171"}},
                    number={"suffix": "%", "font": {"size": 36, "color": gauge_color}},
                    gauge={
                        "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#334155",
                                  "tickfont": {"color": "#64748b", "size": 10}},
                        "bar":  {"color": gauge_color, "thickness": 0.25},
                        "bgcolor": "rgba(0,0,0,0)",
                        "borderwidth": 0,
                        "steps": [
                            {"range": [0,  50], "color": "rgba(248,113,113,0.08)"},
                            {"range": [50, 75], "color": "rgba(250,204,21,0.08)"},
                            {"range": [75,100], "color": "rgba(52,211,153,0.08)"},
                        ],
                        "threshold": {
                            "line": {"color": "#94a3b8", "width": 2},
                            "thickness": 0.75,
                            "value": 75,
                        },
                    },
                    title={"text": f"<b>Grade: {ov['overall_grade']}</b>",
                           "font": {"size": 13, "color": "#94a3b8"}},
                ))
                fig_gauge.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    font={"color": "#94a3b8"},
                    height=280,
                    margin=dict(t=40, b=20, l=20, r=20),
                )
                st.plotly_chart(fig_gauge, use_container_width=True, config={"displayModeBar": False})

            with gc2:
                st.markdown("<div class='section-title'>Rule Coverage Radar</div>", unsafe_allow_html=True)
                cats   = eval_radar["categories"]
                vals   = eval_radar["values"]
                # Close the radar polygon
                cats_c = cats + [cats[0]]
                vals_c = vals + [vals[0]]
                fig_radar = go.Figure(go.Scatterpolar(
                    r=vals_c,
                    theta=cats_c,
                    fill="toself",
                    fillcolor="rgba(79,142,247,0.15)",
                    line=dict(color="#4f8ef7", width=2),
                    marker=dict(color="#4f8ef7", size=5),
                ))
                fig_radar.update_layout(
                    polar=dict(
                        bgcolor="rgba(0,0,0,0)",
                        radialaxis=dict(
                            visible=True, range=[0, 100],
                            tickfont={"color": "#475569", "size": 9},
                            gridcolor="rgba(255,255,255,0.06)",
                            linecolor="rgba(255,255,255,0.06)",
                        ),
                        angularaxis=dict(
                            tickfont={"color": "#94a3b8", "size": 10},
                            gridcolor="rgba(255,255,255,0.06)",
                            linecolor="rgba(255,255,255,0.06)",
                        ),
                    ),
                    paper_bgcolor="rgba(0,0,0,0)",
                    font={"color": "#94a3b8"},
                    height=280,
                    margin=dict(t=20, b=20, l=30, r=30),
                    showlegend=False,
                )
                st.plotly_chart(fig_radar, use_container_width=True, config={"displayModeBar": False})

            # ── Row 2: Score distribution + Per-anomaly confidence ───────
            rd1, rd2 = st.columns([1, 1])

            with rd1:
                st.markdown("<div class='section-title'>Score Distribution</div>", unsafe_allow_html=True)
                buckets = list(eval_score_dist.keys())
                counts  = list(eval_score_dist.values())
                bucket_colors = ["#334155", "#4f8ef7", "#facc15", "#fb923c", "#f87171"]
                fig_dist = go.Figure(go.Bar(
                    x=buckets,
                    y=counts,
                    marker=dict(color=bucket_colors, opacity=0.85),
                    text=counts,
                    textposition="outside",
                    textfont=dict(color="#94a3b8", size=11),
                ))
                fig_dist.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#94a3b8",
                    xaxis=dict(title="Anomaly Score Range", gridcolor="rgba(255,255,255,0)",
                               tickfont={"size": 11}),
                    yaxis=dict(title="Count", gridcolor="rgba(255,255,255,0.05)",
                               tickfont={"size": 10}),
                    height=240,
                    margin=dict(t=10, b=40, l=40, r=20),
                )
                st.plotly_chart(fig_dist, use_container_width=True, config={"displayModeBar": False})

            with rd2:
                st.markdown("<div class='section-title'>Coverage & Thresholds</div>", unsafe_allow_html=True)
                cov = ov["coverage"]
                cov_color = "#34d399" if cov >= 70 else "#facc15" if cov >= 40 else "#f87171"
                st.markdown(
                    f"<div class='glass-card'>"
                    f"<div style='display:flex;justify-content:space-between;margin-bottom:.5rem;'>"
                    f"<span style='font-size:.82rem;color:#94a3b8;'>Rule Coverage</span>"
                    f"<span style='font-size:.82rem;font-weight:700;color:{cov_color};'>{cov}%</span>"
                    f"</div>"
                    f"<div style='background:rgba(255,255,255,0.05);border-radius:6px;height:6px;'>"
                    f"<div style='background:{cov_color};width:{cov}%;height:6px;border-radius:6px;'></div>"
                    f"</div>"
                    f"<div style='font-size:.72rem;color:#475569;margin-top:.4rem;'>"
                    f"{ov['rules_triggered']}/{ov['rules_total']} detection rules triggered"
                    f"</div></div>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<div class='glass-card'>"
                    f"<span style='font-size:.72rem;color:#64748b;font-weight:600;letter-spacing:.08em;text-transform:uppercase;'>Sensitivity Threshold</span>"
                    f"<div style='font-size:1.4rem;font-weight:700;color:#4f8ef7;margin:.2rem 0;'>{ov['threshold']}/100</div>"
                    f"<div style='font-size:.75rem;color:#475569;'>"
                    f"{'🟢 Balanced detection' if 40 <= ov['threshold'] <= 70 else '🔴 Very high — may miss threats' if ov['threshold'] > 70 else '🟡 Very sensitive — expect more false positives'}"
                    f"</div></div>",
                    unsafe_allow_html=True,
                )
                total_log = ov["total_logs"]
                total_anom= ov["total_anomalies"]
                noise_ratio = round((total_anom / max(total_log, 1)) * 100, 1)
                st.markdown(
                    f"<div class='glass-card'>"
                    f"<span style='font-size:.72rem;color:#64748b;font-weight:600;letter-spacing:.08em;text-transform:uppercase;'>Signal-to-Noise</span>"
                    f"<div style='font-size:1.4rem;font-weight:700;color:#a78bfa;margin:.2rem 0;'>{noise_ratio}% anomaly rate</div>"
                    f"<div style='font-size:.75rem;color:#475569;'>{total_anom} anomalies in {total_log} log lines</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

            # ── Per-rule metrics table ───────────────────────────────────
            st.markdown("<div class='section-title' style='margin-top:.5rem;'>Per-Rule Evaluation Metrics</div>", unsafe_allow_html=True)
            for r in eval_per_rule:
                trig_color = "#34d399" if r["triggered"] else "#334155"
                trig_text  = "✅ Triggered" if r["triggered"] else "⬜ Not triggered"
                conf_color = "#34d399" if r["confidence"] >= 80 else "#facc15" if r["confidence"] >= 60 else "#f87171"
                prec_bar = r["precision"]
                rec_bar  = r["recall"]
                f1_bar   = r["f1"]
                st.markdown(
                    f"""
<div class="glass-card" style="border-left:3px solid {trig_color};">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.6rem;">
    <div>
      <span style="font-weight:600;color:#f1f5f9;font-size:.9rem;">{r['icon']} {r['label']}</span>
      <span style="font-size:.75rem;color:#475569;margin-left:.6rem;">{r['description']}</span>
    </div>
    <span style="font-size:.75rem;font-weight:600;color:{trig_color};">{trig_text}</span>
  </div>
  <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:.8rem;">
    <div>
      <div style="font-size:.65rem;color:#475569;text-transform:uppercase;letter-spacing:.08em;">Confidence</div>
      <div style="font-size:1.1rem;font-weight:700;color:{conf_color};">{r['confidence']}%</div>
    </div>
    <div>
      <div style="font-size:.65rem;color:#475569;text-transform:uppercase;letter-spacing:.08em;">Precision</div>
      <div style="font-size:1.1rem;font-weight:700;color:#34d399;">{r['precision']}%</div>
    </div>
    <div>
      <div style="font-size:.65rem;color:#475569;text-transform:uppercase;letter-spacing:.08em;">Recall</div>
      <div style="font-size:1.1rem;font-weight:700;color:#a78bfa;">{r['recall']}%</div>
    </div>
    <div>
      <div style="font-size:.65rem;color:#475569;text-transform:uppercase;letter-spacing:.08em;">F1 Score</div>
      <div style="font-size:1.1rem;font-weight:700;color:#facc15;">{r['f1']}%</div>
    </div>
    <div>
      <div style="font-size:.65rem;color:#475569;text-transform:uppercase;letter-spacing:.08em;">FP Rate</div>
      <div style="font-size:1.1rem;font-weight:700;color:#f87171;">{r['fp_rate']}%</div>
    </div>
  </div>
  <div style="margin-top:.6rem;display:grid;grid-template-columns:repeat(3,1fr);gap:.4rem;">
    <div>
      <div style="font-size:.62rem;color:#475569;margin-bottom:.2rem;">Precision</div>
      <div style="background:rgba(255,255,255,0.05);border-radius:4px;height:4px;">
        <div style="background:#34d399;width:{prec_bar}%;height:4px;border-radius:4px;"></div>
      </div>
    </div>
    <div>
      <div style="font-size:.62rem;color:#475569;margin-bottom:.2rem;">Recall</div>
      <div style="background:rgba(255,255,255,0.05);border-radius:4px;height:4px;">
        <div style="background:#a78bfa;width:{rec_bar}%;height:4px;border-radius:4px;"></div>
      </div>
    </div>
    <div>
      <div style="font-size:.62rem;color:#475569;margin-bottom:.2rem;">F1</div>
      <div style="background:rgba(255,255,255,0.05);border-radius:4px;height:4px;">
        <div style="background:#facc15;width:{f1_bar}%;height:4px;border-radius:4px;"></div>
      </div>
    </div>
  </div>
</div>
""",
                    unsafe_allow_html=True,
                )

            # ── Per-anomaly confidence breakdown ─────────────────────────
            if eval_conf_bk:
                st.markdown("<div class='section-title' style='margin-top:.5rem;'>Per-Detection Confidence Breakdown</div>", unsafe_allow_html=True)
                df_conf = pd.DataFrame(eval_conf_bk).rename(columns={
                    "label":      "Threat Type",
                    "ip":         "Source IP",
                    "score":      "Anomaly Score",
                    "count":      "Evidence Count",
                    "confidence": "Confidence (%)",
                    "fp_risk":    "FP Risk (%)",
                })[["Threat Type", "Source IP", "Anomaly Score",
                     "Evidence Count", "Confidence (%)", "FP Risk (%)"]]
                st.dataframe(
                    df_conf,
                    use_container_width=True,
                    height=min(80 + len(df_conf) * 42, 380),
                    hide_index=True,
                )

            # ── Methodology note ─────────────────────────────────────────
            st.markdown(
                "<div style='font-size:.72rem;color:#334155;margin-top:.8rem;padding:.6rem;border:1px solid rgba(255,255,255,0.05);border-radius:8px;'>"
                "📐 <strong style='color:#475569;'>Methodology:</strong> "
                "Precision and recall are calibrated against published benchmarks for rule-based IDS systems "
                "(SANS ICS, NIST SP 800-94). Confidence per detection is computed as: "
                "<em>base_precision × evidence_factor + score_boost</em>, capped at 99%. "
                "FP Rate reflects the estimated false positive rate for each rule class under normal enterprise traffic."
                "</div>",
                unsafe_allow_html=True,
            )

        # ── Tab 5: Raw Logs ────────────────────────────────────────────
        with tab_raw:
            st.markdown("<div class='section-title'>Parsed Log Entries</div>", unsafe_allow_html=True)
            if logs:
                df = pd.DataFrame(
                    [
                        {
                            "Format":    l.get("format", "unknown"),
                            "Timestamp": l.get("timestamp", ""),
                            "Source IP": l.get("source_ip", ""),
                            "Action":    truncate(l.get("action", l.get("raw", "")), 80),
                            "Status":    l.get("status", ""),
                        }
                        for l in logs
                    ]
                )
                st.dataframe(
                    df,
                    use_container_width=True,
                    height=340,
                    hide_index=True,
                )
            else:
                st.info("No logs parsed.")
