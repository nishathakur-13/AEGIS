import os
import sys
import textwrap
from datetime import datetime

# Ensure root directory is strictly at top of Python search path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

from config.settings import ATTACK_SCENARIOS, COMPLIANCE_MAP, ACTIVE_DATASET, BATADAL_FEATURE_COLUMNS
from src.red_team import RedTeamSimulator
from src.blue_team import BlueTeamEnsemble
from src.uncertainty_engine import EpistemicUncertaintyEngine
from src.mitigation_engine import MitigationEngine
from src.compliance_logger import ComplianceAuditLogger
from src.ablation_study import AblationBenchmarkEngine
from src.physics_twin import PhysicsInformedDigitalTwin, IntegratedSafetyReportEngine
from src.zero_day_generator import ConditionalDiffusionGenerator

# =========================================================================
# PAGE CONFIGURATION
# =========================================================================
st.set_page_config(
    page_title="AEGIS | SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =========================================================================
# DESIGN TOKENS
# =========================================================================
COLOR_VOID      = "#0A0E14"   # page background
COLOR_PANEL     = "#10151F"   # card / panel background
COLOR_PANEL_ALT = "#141A26"   # secondary panel
COLOR_PANEL_HOVER = "#171E2C" # panel hover state
COLOR_BORDER    = "#1E2530"   # hairline borders
COLOR_BORDER_HL = "#2A3342"   # slightly brighter border for hover
COLOR_TEXT      = "#E6EDF3"   # primary text
COLOR_MUTED     = "#7C8896"   # secondary text
COLOR_FAINT     = "#4B5561"   # tertiary / disabled text
COLOR_SAFE      = "#00D9A3"   # teal green - clean / benign
COLOR_CRITICAL  = "#FF3B5C"   # alert red - threat
COLOR_WARNING   = "#FFB020"   # amber - human action required
COLOR_INFO      = "#3B9EFF"   # blue - informational / neutral telemetry
SHADOW_SOFT     = "0 8px 24px -8px rgba(0,0,0,0.45)"
SHADOW_LIFT     = "0 16px 36px -12px rgba(0,0,0,0.55)"


def md(html: str):
    """st.markdown wrapper that strips common leading indentation before
    rendering, so multi-line HTML from indented f-strings never gets
    misread as a Markdown indented code block."""
    st.markdown(textwrap.dedent(html).strip(), unsafe_allow_html=True)


# =========================================================================
# GLOBAL STYLE INJECTION
# =========================================================================
md(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700;800&display=swap');

* {{
    box-sizing: border-box;
}}

html, body, [class*="css"] {{
    font-family: 'Inter', sans-serif;
}}

.stApp {{
    background:
        radial-gradient(ellipse 900px 500px at 15% -10%, rgba(59,158,255,0.07), transparent),
        radial-gradient(ellipse 900px 500px at 100% 0%, rgba(0,217,163,0.06), transparent),
        radial-gradient(ellipse 700px 400px at 50% 100%, rgba(255,59,92,0.03), transparent),
        {COLOR_VOID};
}}

/* ---------- Scrollbar ---------- */
::-webkit-scrollbar {{ width: 10px; height: 10px; }}
::-webkit-scrollbar-track {{ background: {COLOR_VOID}; }}
::-webkit-scrollbar-thumb {{
    background: {COLOR_BORDER_HL};
    border-radius: 8px;
    border: 2px solid {COLOR_VOID};
}}
::-webkit-scrollbar-thumb:hover {{ background: {COLOR_MUTED}; }}

#MainMenu, header {{visibility: hidden;}}
footer {{visibility: hidden;}}

section[data-testid="stSidebar"] {{
    background: {COLOR_PANEL};
    border-right: 1px solid {COLOR_BORDER};
}}
section[data-testid="stSidebar"] .block-container {{
    padding-top: 1.6rem;
}}

.block-container {{
    padding-top: 1.4rem;
    padding-bottom: 3rem;
    max-width: 1400px;
}}

/* ---------- Focus visibility (accessibility) ---------- */
button:focus-visible, a:focus-visible, [tabindex]:focus-visible {{
    outline: 2px solid {COLOR_INFO} !important;
    outline-offset: 2px;
}}

/* ---------- Eyebrow / tracked labels ---------- */
.rs-eyebrow {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: {COLOR_MUTED};
    margin-bottom: 0.35rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}}
.rs-eyebrow::before {{
    content: "";
    width: 14px;
    height: 1px;
    background: {COLOR_INFO};
    display: inline-block;
}}

/* ---------- Header ---------- */
.rs-header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    padding-bottom: 1.1rem;
    border-bottom: 1px solid {COLOR_BORDER};
    margin-bottom: 1.6rem;
}}
.rs-title {{
    font-family: 'JetBrains Mono', monospace;
    font-weight: 800;
    font-size: 1.9rem;
    color: {COLOR_TEXT};
    letter-spacing: -0.02em;
    margin: 0;
}}
.rs-title span {{
    background: linear-gradient(120deg, {COLOR_INFO}, {COLOR_SAFE});
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}}
.rs-subtitle {{
    color: {COLOR_MUTED};
    font-size: 0.92rem;
    margin-top: 0.15rem;
}}
.rs-version-tag {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    color: {COLOR_FAINT};
    background: {COLOR_PANEL_ALT};
    border: 1px solid {COLOR_BORDER};
    padding: 0.12rem 0.4rem;
    border-radius: 4px;
    margin-left: 0.55rem;
    vertical-align: middle;
    text-transform: uppercase;
}}
.rs-status-pill {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    color: {COLOR_SAFE};
    background: rgba(0,217,163,0.10);
    border: 1px solid rgba(0,217,163,0.35);
    padding: 0.4rem 0.8rem;
    border-radius: 999px;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    box-shadow: 0 0 0 4px rgba(0,217,163,0.04);
}}
.rs-dot {{
    width: 7px; height: 7px; border-radius: 50%;
    background: {COLOR_SAFE};
    box-shadow: 0 0 0 0 rgba(0,217,163,0.6);
    animation: rs-pulse 1.8s infinite;
}}
@keyframes rs-pulse {{
    0%   {{ box-shadow: 0 0 0 0 rgba(0,217,163,0.55); }}
    70%  {{ box-shadow: 0 0 0 7px rgba(0,217,163,0); }}
    100% {{ box-shadow: 0 0 0 0 rgba(0,217,163,0); }}
}}
.rs-timestamp {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: {COLOR_MUTED};
    text-align: right;
    margin-top: 0.4rem;
}}

/* ---------- KPI cards ---------- */
.rs-card {{
    background: linear-gradient(180deg, {COLOR_PANEL_ALT}, {COLOR_PANEL});
    border: 1px solid {COLOR_BORDER};
    border-left: 3px solid var(--accent, {COLOR_INFO});
    border-radius: 10px;
    padding: 1.05rem 1.15rem;
    height: 100%;
    transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
    position: relative;
    overflow: hidden;
}}
.rs-card::after {{
    content: "";
    position: absolute;
    top: -40%; right: -20%;
    width: 120px; height: 120px;
    background: radial-gradient(circle, var(--accent, {COLOR_INFO}) 0%, transparent 70%);
    opacity: 0.06;
    pointer-events: none;
}}
.rs-card:hover {{
    transform: translateY(-2px);
    box-shadow: {SHADOW_SOFT};
    border-color: {COLOR_BORDER_HL};
}}
.rs-card-top {{
    display: flex;
    align-items: center;
    justify-content: space-between;
}}
.rs-card-label {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: {COLOR_MUTED};
    margin-bottom: 0.5rem;
}}
.rs-card-icon {{
    font-size: 0.95rem;
    opacity: 0.75;
}}
.rs-card-value {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.65rem;
    font-weight: 700;
    color: {COLOR_TEXT};
    line-height: 1.1;
    letter-spacing: -0.01em;
}}
.rs-card-delta {{
    font-size: 0.78rem;
    font-weight: 600;
    margin-top: 0.5rem;
    display: flex;
    align-items: center;
    gap: 0.35rem;
}}

/* ---------- Section panel ---------- */
.rs-panel {{
    background: {COLOR_PANEL};
    border: 1px solid {COLOR_BORDER};
    border-radius: 12px;
    padding: 1.3rem 1.4rem;
    height: 100%;
    transition: border-color 0.18s ease;
}}
.rs-panel-title {{
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    font-size: 0.95rem;
    color: {COLOR_TEXT};
    margin-bottom: 0.9rem;
    padding-bottom: 0.75rem;
    border-bottom: 1px solid {COLOR_BORDER};
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
}}
.rs-panel-title-tag {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: {COLOR_MUTED};
    background: {COLOR_PANEL_ALT};
    border: 1px solid {COLOR_BORDER};
    padding: 0.18rem 0.5rem;
    border-radius: 999px;
}}

/* ---------- Verdict banner ---------- */
.rs-banner {{
    border-radius: 12px;
    padding: 1.1rem 1.4rem;
    margin-bottom: 1.4rem;
    border: 1px solid var(--accent, {COLOR_INFO});
    background: var(--accent-bg, rgba(59,158,255,0.08));
    display: flex;
    align-items: center;
    gap: 1rem;
    box-shadow: {SHADOW_SOFT};
}}
.rs-banner-icon-wrap {{
    width: 42px;
    height: 42px;
    min-width: 42px;
    border-radius: 10px;
    background: rgba(255,255,255,0.06);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.4rem;
}}
.rs-banner-title {{
    font-weight: 700;
    font-size: 1.02rem;
    color: {COLOR_TEXT};
}}
.rs-banner-sub {{
    font-size: 0.85rem;
    color: {COLOR_MUTED};
    margin-top: 0.2rem;
    line-height: 1.45;
}}

/* ---------- Compliance badges ---------- */
.rs-badge-row {{ display: flex; flex-wrap: wrap; gap: 0.55rem; }}
.rs-badge {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    font-weight: 600;
    color: {COLOR_INFO};
    background: rgba(59,158,255,0.10);
    border: 1px solid rgba(59,158,255,0.35);
    padding: 0.34rem 0.7rem;
    border-radius: 6px;
    transition: background 0.15s ease, transform 0.15s ease;
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
}}
.rs-badge:hover {{
    background: rgba(59,158,255,0.18);
    transform: translateY(-1px);
}}
.rs-badge::before {{ content: "\\2713"; font-size: 0.68rem; opacity: 0.85; }}

/* ---------- Buttons ---------- */
.stButton > button {{
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    letter-spacing: 0.02em;
    border-radius: 8px;
    border: 1px solid {COLOR_BORDER};
    transition: transform 0.12s ease, box-shadow 0.12s ease, border-color 0.12s ease;
}}
.stButton > button:hover {{
    transform: translateY(-1px);
    border-color: {COLOR_BORDER_HL};
    box-shadow: {SHADOW_SOFT};
}}
.stButton > button:active {{
    transform: translateY(0);
}}
.stButton > button[kind="primary"] {{
    background: linear-gradient(135deg, {COLOR_INFO}, #2E7FDB);
    border: none;
}}

/* ---------- Tabs ---------- */
.stTabs [data-baseweb="tab-list"] {{
    gap: 0.4rem;
    border-bottom: 1px solid {COLOR_BORDER};
}}
.stTabs [data-baseweb="tab"] {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    font-weight: 600;
    color: {COLOR_MUTED};
    transition: color 0.15s ease;
}}
.stTabs [data-baseweb="tab"]:hover {{
    color: {COLOR_TEXT};
}}
.stTabs [aria-selected="true"] {{
    color: {COLOR_INFO} !important;
}}
.stTabs [data-baseweb="tab-highlight"] {{
    background-color: {COLOR_INFO} !important;
}}

/* ---------- Code blocks ---------- */
code {{
    font-family: 'JetBrains Mono', monospace !important;
}}

hr {{ border-color: {COLOR_BORDER}; }}

/* ---------- Dataframes ---------- */
[data-testid="stDataFrame"] {{
    border: 1px solid {COLOR_BORDER};
    border-radius: 10px;
    overflow: hidden;
}}

/* ---------- Alerts ---------- */
div[data-testid="stAlert"] {{
    border-radius: 10px;
    border: 1px solid {COLOR_BORDER};
}}

/* ---------- Selectbox / dropdown ---------- */
.stSelectbox label {{
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.68rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase;
    color: {COLOR_MUTED} !important;
}}
div[data-baseweb="select"] > div {{
    background: {COLOR_PANEL_ALT} !important;
    border: 1px solid {COLOR_BORDER} !important;
    border-radius: 8px !important;
    min-height: 2.65rem;
    font-family: 'JetBrains Mono', monospace !important;
    color: {COLOR_TEXT} !important;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
}}
div[data-baseweb="select"] > div:hover {{
    border-color: {COLOR_INFO} !important;
}}
div[data-baseweb="select"] > div:focus-within {{
    border-color: {COLOR_INFO} !important;
    box-shadow: 0 0 0 3px rgba(59,158,255,0.18) !important;
}}
div[data-baseweb="select"] span {{
    color: {COLOR_TEXT} !important;
    font-size: 0.86rem !important;
}}
div[data-baseweb="select"] svg {{
    fill: {COLOR_INFO} !important;
}}
ul[role="listbox"] {{
    background: {COLOR_PANEL} !important;
    border: 1px solid {COLOR_BORDER} !important;
    border-radius: 8px !important;
    box-shadow: 0 12px 28px rgba(0,0,0,0.45) !important;
}}
li[role="option"] {{
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.84rem !important;
    color: {COLOR_TEXT} !important;
}}
li[role="option"]:hover {{
    background: rgba(59,158,255,0.14) !important;
    color: {COLOR_INFO} !important;
}}
li[aria-selected="true"] {{
    background: rgba(59,158,255,0.10) !important;
    color: {COLOR_INFO} !important;
}}

/* ---------- Sidebar mission card ---------- */
.rs-sidebar-card {{
    background: {COLOR_PANEL_ALT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 10px;
    padding: 0.9rem 1rem;
    margin-bottom: 1rem;
}}
.rs-sidebar-row {{
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 0.7rem;
}}
.rs-sidebar-row:last-child {{ margin-bottom: 0; }}
.rs-sidebar-row-value {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.86rem;
    text-align: right;
}}

/* ---------- Legend ---------- */
.rs-legend-item {{
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.3rem 0;
    font-size: 0.82rem;
    color: {COLOR_MUTED};
}}
.rs-legend-dot {{
    width: 8px; height: 8px; border-radius: 50%; min-width: 8px;
}}

/* ---------- Animated bar chart ---------- */
.rs-chart-track {{
    display: flex;
    align-items: flex-end;
    justify-content: space-around;
    gap: 0.9rem;
    height: 230px;
    padding: 0 0.4rem;
    border-bottom: 1px solid {COLOR_BORDER};
    position: relative;
}}
.rs-chart-track::before {{
    content: "";
    position: absolute;
    left: 0; right: 0; top: 25%;
    border-top: 1px dashed {COLOR_BORDER};
}}
.rs-chart-track::after {{
    content: "";
    position: absolute;
    left: 0; right: 0; top: 62.5%;
    border-top: 1px dashed {COLOR_BORDER};
}}
.rs-chart-col {{
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: flex-end;
    height: 100%;
    flex: 1;
    min-width: 0;
}}
.rs-chart-value {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    font-weight: 700;
    color: {COLOR_TEXT};
    margin-bottom: 0.4rem;
    opacity: 0;
    animation: rs-fade-in 0.4s ease forwards;
    animation-delay: var(--delay);
}}
.rs-chart-bar {{
    width: 58%;
    max-width: 44px;
    border-radius: 6px 6px 2px 2px;
    height: 0;
    animation: rs-rise 0.85s cubic-bezier(0.22, 1.4, 0.36, 1) forwards;
    animation-delay: var(--delay);
    box-shadow: 0 0 14px -3px var(--glow);
    transition: filter 0.15s ease, transform 0.15s ease;
    cursor: default;
}}
.rs-chart-bar:hover {{
    filter: brightness(1.15);
    transform: scaleX(1.06);
}}
.rs-chart-label {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.66rem;
    font-weight: 600;
    letter-spacing: 0.03em;
    color: {COLOR_MUTED};
    margin-top: 0.55rem;
    text-align: center;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 100%;
}}
@keyframes rs-rise {{
    from {{ height: 0; opacity: 0.4; }}
    to   {{ height: var(--h); opacity: 1; }}
}}
@keyframes rs-fade-in {{
    from {{ opacity: 0; transform: translateY(4px); }}
    to   {{ opacity: 1; transform: translateY(0); }}
}}

/* ---------- Footer signature ---------- */
.rs-footer {{
    margin-top: 2.4rem;
    padding-top: 1.1rem;
    border-top: 1px solid {COLOR_BORDER};
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    color: {COLOR_FAINT};
    letter-spacing: 0.04em;
}}
</style>
""")


# =========================================================================
# RENDER HELPERS
# =========================================================================
def kpi_card(label: str, value: str, delta: str, tone: str = "info", icon: str = "▣"):
    accent = {"safe": COLOR_SAFE, "critical": COLOR_CRITICAL,
              "warning": COLOR_WARNING, "info": COLOR_INFO}[tone]
    md(f"""
    <div class="rs-card" style="--accent:{accent}">
        <div class="rs-card-top">
            <div class="rs-card-label">{label}</div>
            <div class="rs-card-icon" style="color:{accent}">{icon}</div>
        </div>
        <div class="rs-card-value">{value}</div>
        <div class="rs-card-delta" style="color:{accent}">{delta}</div>
    </div>
    """)


def verdict_banner(is_benign: bool, attack_name: str = None):
    if is_benign:
        md(f"""
        <div class="rs-banner" style="--accent:{COLOR_SAFE}; --accent-bg:rgba(0,217,163,0.08)">
            <div class="rs-banner-icon-wrap">🟢</div>
            <div>
                <div class="rs-banner-title">Benign telemetry confirmed — normal grid operations</div>
                <div class="rs-banner-sub">Threat probability below decision threshold. No firewall rules applied — grid traffic flows uninterrupted at zero added latency.</div>
            </div>
        </div>
        """)
    else:
        md(f"""
        <div class="rs-banner" style="--accent:{COLOR_CRITICAL}; --accent-bg:rgba(255,59,92,0.08)">
            <div class="rs-banner-icon-wrap">🚨</div>
            <div>
                <div class="rs-banner-title">Malicious threat detected — {attack_name}</div>
                <div class="rs-banner-sub">Ensemble consensus exceeded the critical threshold. A candidate defense patch has been pre-validated in the digital twin sandbox.</div>
            </div>
        </div>
        """)


def styled_probability_chart(df_probs: pd.DataFrame, is_benign: bool):
    """Custom CSS-animated bar chart — bars rise up from the baseline on render."""
    accent = COLOR_SAFE if is_benign else COLOR_CRITICAL
    accent_dim = "#1E2530"
    max_val = max(float(df_probs['Probability (%)'].max()), 1.0)

    cols_html = []
    for i, row in df_probs.iterrows():
        model = row['Model']
        val = float(row['Probability (%)'])
        height_pct = max((val / max(max_val, 100.0)) * 100, 2)  # relative to a 100% ceiling, min visible sliver
        intensity = min(val / 100.0, 1.0)
        bar_color = accent if intensity > 0.15 else accent_dim
        delay = f"{i * 0.11:.2f}s"
        value_color = bar_color if intensity > 0.15 else COLOR_MUTED
        col_html = (
            '<div class="rs-chart-col">'
            f'<div class="rs-chart-value" style="--delay:{delay}; color:{value_color};">{val:.1f}%</div>'
            f'<div class="rs-chart-bar" title="{model}: {val:.1f}%" style="--h:{height_pct:.1f}%; --delay:{delay}; --glow:{bar_color}; '
            f'background: linear-gradient(180deg, {bar_color}, {accent_dim});"></div>'
            f'<div class="rs-chart-label">{model}</div>'
            '</div>'
        )
        cols_html.append(col_html)

    chart_html = '<div class="rs-chart-track">' + "".join(cols_html) + '</div>'
    st.markdown(chart_html, unsafe_allow_html=True)


def compliance_badges(compliance_map: dict):
    keys = list(compliance_map.keys())
    if not keys:
        return
    badges_html = "".join(f'<div class="rs-badge">{k}</div>' for k in keys)
    st.markdown(f'<div class="rs-badge-row">{badges_html}</div>', unsafe_allow_html=True)


def app_footer():
    md(f"""
    <div class="rs-footer">
        <span>AEGIS · PURPLE TEAM RESEARCH BUILD</span>
        <span>UNCERTAINTY-AWARE · ZERO-DISRUPTION · HUMAN-IN-THE-LOOP</span>
    </div>
    """)


# =========================================================================
# INSTANTIATE CORE ENGINES (CACHED)
# =========================================================================
@st.cache_resource
def load_aegis_core():
    red_agent = RedTeamSimulator()
    blue_ensemble = BlueTeamEnsemble()
    if not blue_ensemble.load_models():
        blue_ensemble.train_models()
    uncertainty_engine = EpistemicUncertaintyEngine()
    mitigation_engine = MitigationEngine()
    logger = ComplianceAuditLogger()
    ablation_engine = AblationBenchmarkEngine()
    physics_twin = PhysicsInformedDigitalTwin()
    diffusion_gen = ConditionalDiffusionGenerator()
    integrated_report_engine = IntegratedSafetyReportEngine()
    return red_agent, blue_ensemble, uncertainty_engine, mitigation_engine, logger, ablation_engine, physics_twin, diffusion_gen, integrated_report_engine

red_agent, blue_ensemble, uncertainty_engine, mitigation_engine, logger, ablation_engine, physics_twin, diffusion_gen, integrated_report_engine = load_aegis_core()

# =========================================================================
# HEADER
# =========================================================================
header_left, header_right = st.columns([3, 1])
with header_left:
    st.markdown('<div class="rs-eyebrow">PURPLE TEAM · CRITICAL INFRASTRUCTURE DEFENSE</div>', unsafe_allow_html=True)
    st.markdown('<h1 class="rs-title">🛡️ <span>AEGIS</span> <span class="rs-version-tag">v2.1 · Research</span></h1>', unsafe_allow_html=True)
    st.markdown('<div class="rs-subtitle">Adaptive Ensemble for Grid Intrusion Shielding — Uncertainty-aware, zero-disruption cyber defense for the power grid</div>', unsafe_allow_html=True)
with header_right:
    st.markdown('<div style="text-align:right;"><span class="rs-status-pill"><span class="rs-dot"></span> ENSEMBLE ONLINE</span></div>', unsafe_allow_html=True)
    st.markdown(f'<div class="rs-timestamp">LAST SYNC · {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>', unsafe_allow_html=True)
st.markdown('<hr style="margin-top:0.9rem; margin-bottom:1.5rem;">', unsafe_allow_html=True)

# =========================================================================
# TOP LEVEL NAVIGATION TABS
# =========================================================================
main_tab1, main_tab2, main_tab3 = st.tabs(["🕹️ Live SOC Operations", "🔬 Research Experiments & Ablation Study", "🧬 GenAI Zero-Day Lab"])

# =========================================================================
# TAB 1: LIVE SOC OPERATIONS
# =========================================================================
with main_tab1:
    # ---------------- SIDEBAR CONTROLS ----------------
    st.sidebar.markdown('<div class="rs-eyebrow">MISSION CONTROL</div>', unsafe_allow_html=True)
    st.sidebar.markdown('#### 🕹️ Simulation Controls')

    selected_scenario_key = st.sidebar.selectbox(
        "Select telemetry / scenario",
        options=list(ATTACK_SCENARIOS.keys()),
        format_func=lambda x: f"{ATTACK_SCENARIOS[x]['id']} — {ATTACK_SCENARIOS[x]['name']}"
    )
    scenario_info = ATTACK_SCENARIOS[selected_scenario_key]

    st.sidebar.markdown(f"""
    <div class="rs-sidebar-card">
        <div class="rs-sidebar-row">
            <span class="rs-card-label" style="margin-bottom:0;">Target node</span>
            <span class="rs-sidebar-row-value" style="color:{COLOR_TEXT};">{scenario_info['target']}</span>
        </div>
        <div class="rs-sidebar-row">
            <span class="rs-card-label" style="margin-bottom:0;">Severity level</span>
            <span class="rs-sidebar-row-value" style="color:{COLOR_WARNING};">{scenario_info['severity']}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    trigger_simulation = st.sidebar.button("🚀 Trigger Simulation", use_container_width=True, type="primary")

    st.sidebar.markdown('<hr>', unsafe_allow_html=True)
    st.sidebar.markdown('<div class="rs-eyebrow">Legend</div>', unsafe_allow_html=True)
    st.sidebar.markdown(f"""
    <div class="rs-legend-item"><span class="rs-legend-dot" style="background:{COLOR_SAFE};"></span> Clean / no action needed</div>
    <div class="rs-legend-item"><span class="rs-legend-dot" style="background:{COLOR_CRITICAL};"></span> Active threat, patch pending</div>
    <div class="rs-legend-item"><span class="rs-legend-dot" style="background:{COLOR_WARNING};"></span> Human authorization required</div>
    """, unsafe_allow_html=True)

    # ---------------- SESSION STATE MANAGEMENT ----------------
    if 'simulation_run' not in st.session_state:
        st.session_state.simulation_run = False

    if trigger_simulation:
        st.session_state.simulation_run = True
        attack_payload = red_agent.generate_attack_payload(selected_scenario_key)
        st.session_state.attack_payload = attack_payload

        df_attack = red_agent.payload_to_dataframe(attack_payload)
        st.session_state.df_attack = df_attack
        probs = blue_ensemble.predict_probabilities(df_attack)
        st.session_state.probs = probs

        uncertainty_eval = uncertainty_engine.evaluate_uncertainty(probs)
        st.session_state.uncertainty_eval = uncertainty_eval

        patch = mitigation_engine.generate_candidate_patch(selected_scenario_key)
        patch_report = mitigation_engine.pre_validate_patch(attack_payload, patch)
        st.session_state.patch_report = patch_report

        # --- PHYSICS-INFORMED DIGITAL TWIN EVALUATION ---
        phys_telemetry = {
            'voltage_kv':        attack_payload.get('voltage',        138.0),
            'current_amps':      attack_payload.get('current',        500.0),
            'active_power_mw':   attack_payload.get('active_power',   110.0),
            'reactive_power_mvar': attack_payload.get('reactive_power', 30.0),
        }
        physics_verification = physics_twin.verify_physical_laws(phys_telemetry)

        action_type   = "FULL_NODE_ISOLATION" if selected_scenario_key in ["FDIA_ATTACK", "FDIA_PHYSICS_FAILURE"] else "DYNAMIC_MICRO_SEGMENTATION"
        current_load  = phys_telemetry['active_power_mw']
        physics_safety = physics_twin.simulate_mitigation_safety(
            target_node=scenario_info['target'],
            action_type=action_type,
            current_load_mw=current_load,
        )

        # ── Component 3: Integrated Safety Report (ML + Physics fusion) ──
        integrated_report = integrated_report_engine.generate_report(
            ml_eval      = uncertainty_eval,
            phys_verify  = physics_verification,
            phys_safety  = physics_safety,
            patch_report = patch_report,
        )

        st.session_state.physics_verification = physics_verification
        st.session_state.physics_safety       = physics_safety
        st.session_state.integrated_report    = integrated_report

    # ---------------- MAIN DASHBOARD BODY ----------------
    if st.session_state.simulation_run:
        attack    = st.session_state.attack_payload
        u_eval    = st.session_state.uncertainty_eval
        p_report  = st.session_state.patch_report
        p_ver     = st.session_state.get('physics_verification', {})
        p_safe    = st.session_state.get('physics_safety', {})
        i_report  = st.session_state.get('integrated_report', {})

        is_benign = selected_scenario_key == 'BENIGN_TRAFFIC' or u_eval['composite_threat_score'] < 0.25

        verdict_banner(is_benign, attack.get('attack_name') if not is_benign else None)

        # ---------------- KPI ROW ----------------
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            kpi_card(
                "Composite Threat Score",
                f"{u_eval['composite_threat_score'] * 100:.1f}%",
                "✓ Safe / Clean" if is_benign else "⚠ Critical Threat",
                "safe" if is_benign else "critical",
                icon="◆"
            )
        with col2:
            kpi_card(
                "Epistemic Variance (σ²)",
                f"{u_eval['epistemic_uncertainty_variance']:.6f}",
                "High model consensus",
                "info",
                icon="≈"
            )
        with col3:
            kpi_card(
                "Network Action",
                "PASS / NO BLOCK" if is_benign else "BLOCK THREAT",
                "Clean traffic" if is_benign else f"{p_report['security_gain_pct']}% blocked",
                "safe" if is_benign else "critical",
                icon="⛨"
            )
        with col4:
            grid_impact = "87.5% (CRITICAL)" if not p_safe.get('is_physically_safe', True) else f"{p_report['grid_disruption_pct']}%"
            kpi_card(
                "Grid Operational Risk",
                grid_impact,
                "Outage Hazard!" if not p_safe.get('is_physically_safe', True) else "Zero Disruption",
                "critical" if not p_safe.get('is_physically_safe', True) else ("warning" if not is_benign else "safe"),
                icon="⚡"
            )

        st.markdown('<div style="height:1.4rem;"></div>', unsafe_allow_html=True)

        # ---------------- INTEGRATED SAFETY REPORT ----------------
        if i_report:
            cri       = i_report.get("combined_risk_index", 0.0)
            i_verdict = i_report.get("final_verdict", "UNKNOWN")
            i_color   = {
                "CRITICAL_CONFIRMED": COLOR_CRITICAL,
                "HIGH_THREAT":        COLOR_CRITICAL,
                "AMBIGUOUS_MONITOR":  COLOR_WARNING,
                "BENIGN_CLEAR":       COLOR_SAFE,
            }.get(i_verdict, COLOR_MUTED)
            gate_note = (
                f'<br><span style="color:{COLOR_WARNING}; font-size:0.78rem;">⚠ Physics Safety Gate triggered — '
                f'action downgraded to DYNAMIC_MICRO_SEGMENTATION to prevent blackout</span>'
            ) if i_report.get("physics_gate_triggered") else ""

            _cri_str         = f"{cri:.4f}"
            _confidence      = i_report.get('confidence_pct', 0)
            _approval_color  = '#FF9500' if i_report.get('human_approval_required') else COLOR_SAFE
            _approval_text   = 'REQUIRED' if i_report.get('human_approval_required') else 'NOT REQUIRED'
            _rec_action      = i_report.get('recommended_action', 'N/A')
            _ml_score        = f"{i_report.get('ml_threat_score', 0) * 100:.1f}%"
            _phys_score      = f"{i_report.get('physics_anomaly_score', 0) * 100:.1f}%"
            _freq_score      = f"{i_report.get('frequency_score', 0) * 100:.1f}%"
            _xfmr_score      = f"{i_report.get('transformer_score', 0) * 100:.1f}%"
            _kcl_color       = '#FF3B5C' if i_report.get('overcurrent_detected') else COLOR_SAFE
            _kcl_text        = 'YES' if i_report.get('overcurrent_detected') else 'NO'
            _line_stress     = f"{i_report.get('line_stress_pct', 0):.1f}%"
            _freq_hz         = f"{i_report.get('frequency_hz', 50.0):.3f} Hz"
            _freq_dev        = f"{i_report.get('frequency_deviation_hz', 0.0):+.3f} Hz"
            _freq_color      = '#FF3B5C' if i_report.get('frequency_outside_band') else COLOR_SAFE
            _xfmr_pct        = f"{i_report.get('transformer_loading_pct_live', 0):.1f}%"
            _xfmr_color      = '#FF3B5C' if i_report.get('transformer_overloaded_live') else COLOR_TEXT
            _brk_color       = '#FF3B5C' if i_report.get('breaker_tripped') else COLOR_SAFE
            _brk_text        = 'TRIPPED' if i_report.get('breaker_tripped') else 'CLOSED'
            _pf              = f"{i_report.get('power_factor', 1.0):.3f}"
            _vband_color     = {'NORMAL': COLOR_SAFE, 'WARNING': COLOR_WARNING, 'CRITICAL': COLOR_CRITICAL}.get(
                                i_report.get('voltage_band', 'NORMAL'), COLOR_MUTED)

            st.markdown(
                f'<div class="rs-panel" style="border-color:{i_color}; margin-bottom:1.2rem;">'
                f'<div class="rs-panel-title">🔬 Integrated Safety Report'
                f'<span class="rs-panel-title-tag">Component 3 · ML + Physics Fusion</span></div>'

                # Row 1: CRI + Verdict + Action + Signal breakdown
                f'<div style="display:flex; gap:1.5rem; align-items:center; flex-wrap:wrap; margin-bottom:1rem;">'

                f'<div>'
                f'<div class="rs-card-label">Combined Risk Index (CRI)</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:2rem; font-weight:800; color:{i_color}; line-height:1.1;">{_cri_str}</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.66rem; color:{COLOR_MUTED};">0.45×ML + 0.30×Physics + 0.10×KCL + 0.10×Freq + 0.05×Xfmr</div>'
                f'</div>'

                f'<div style="flex:1; min-width:180px;">'
                f'<div class="rs-card-label">Final Unified Verdict</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:1.1rem; font-weight:700; color:{i_color}; margin-bottom:0.3rem;">{i_verdict}</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.78rem; color:{COLOR_MUTED};">'
                f'Confidence: <b style="color:{COLOR_TEXT};">{_confidence}%</b>'
                f'&nbsp;·&nbsp;'
                f'Human Approval: <b style="color:{_approval_color};">{_approval_text}</b>'
                f'</div>'
                f'</div>'

                f'<div style="flex:1; min-width:180px;">'
                f'<div class="rs-card-label">Recommended Action</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.82rem; color:{COLOR_TEXT}; line-height:1.5;">'
                f'{_rec_action}{gate_note}'
                f'</div>'
                f'</div>'

                f'<div>'
                f'<div class="rs-card-label">Signal Breakdown (5-factor)</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.78rem; color:{COLOR_MUTED}; line-height:1.8;">'
                f'ML Threat (45%):&nbsp;&nbsp;&nbsp;<b style="color:{COLOR_TEXT};">{_ml_score}</b><br>'
                f'Physics (30%):&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b style="color:{COLOR_TEXT};">{_phys_score}</b><br>'
                f'KCL Overcurrent (10%):&nbsp;<b style="color:{_kcl_color};">{_kcl_text}</b><br>'
                f'Frequency (10%):&nbsp;&nbsp;&nbsp;&nbsp;<b style="color:{_freq_color};">{_freq_score}</b><br>'
                f'Transformer (5%):&nbsp;&nbsp;&nbsp;<b style="color:{_xfmr_color};">{_xfmr_score}</b>'
                f'</div>'
                f'</div>'
                f'</div>'

                # Row 2: Detailed electrical metrics grid
                f'<div style="border-top:1px solid {COLOR_BORDER}; padding-top:0.75rem; margin-top:0.25rem;">'
                f'<div class="rs-card-label" style="margin-bottom:0.5rem;">⚡ Electrical State Snapshot</div>'
                f'<div style="display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:0.6rem;">'

                f'<div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:8px; padding:0.55rem 0.7rem;">'
                f'<div class="rs-card-label" style="font-size:0.62rem;">Frequency</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.92rem; font-weight:700; color:{_freq_color};">{_freq_hz}</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.65rem; color:{COLOR_MUTED};">Δ {_freq_dev}</div>'
                f'</div>'

                f'<div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:8px; padding:0.55rem 0.7rem;">'
                f'<div class="rs-card-label" style="font-size:0.62rem;">Power Factor</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.92rem; font-weight:700; color:{COLOR_TEXT};">{_pf}</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.65rem; color:{COLOR_MUTED};">unity=1.0</div>'
                f'</div>'

                f'<div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:8px; padding:0.55rem 0.7rem;">'
                f'<div class="rs-card-label" style="font-size:0.62rem;">Voltage Band</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.92rem; font-weight:700; color:{_vband_color};">'
                f'{i_report.get("voltage_band","N/A")}</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.65rem; color:{COLOR_MUTED};">'
                f'{i_report.get("voltage_deviation_pct",0):.2f}% dev</div>'
                f'</div>'

                f'<div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:8px; padding:0.55rem 0.7rem;">'
                f'<div class="rs-card-label" style="font-size:0.62rem;">Transformer Load</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.92rem; font-weight:700; color:{_xfmr_color};">{_xfmr_pct}</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.65rem; color:{COLOR_MUTED};">trip@110%</div>'
                f'</div>'

                f'<div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:8px; padding:0.55rem 0.7rem;">'
                f'<div class="rs-card-label" style="font-size:0.62rem;">Breaker Status</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.92rem; font-weight:700; color:{_brk_color};">{_brk_text}</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.65rem; color:{COLOR_MUTED};">relay protection</div>'
                f'</div>'

                f'<div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:8px; padding:0.55rem 0.7rem;">'
                f'<div class="rs-card-label" style="font-size:0.62rem;">Line Loading</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.92rem; font-weight:700; '
                f'color:{COLOR_CRITICAL if i_report.get("line_loading_pct",0)>100 else COLOR_TEXT};">'
                f'{i_report.get("line_loading_pct",0):.1f}%</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.65rem; color:{COLOR_MUTED};">of line capacity</div>'
                f'</div>'

                f'<div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:8px; padding:0.55rem 0.7rem;">'
                f'<div class="rs-card-label" style="font-size:0.62rem;">Active Power</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.92rem; font-weight:700; color:{COLOR_TEXT};">'
                f'{i_report.get("active_power_mw",0):.1f} MW</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.65rem; color:{COLOR_MUTED};">P</div>'
                f'</div>'

                f'<div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:8px; padding:0.55rem 0.7rem;">'
                f'<div class="rs-card-label" style="font-size:0.62rem;">Reactive Power</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.92rem; font-weight:700; '
                f'color:{COLOR_WARNING if i_report.get("high_reactive_flag") else COLOR_TEXT};">'
                f'{i_report.get("reactive_power_mvar",0):.1f} MVAr</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.65rem; color:{COLOR_MUTED};">Q · ratio={i_report.get("reactive_ratio",0):.2f}</div>'
                f'</div>'

                f'</div>'   # end grid
                f'</div>'   # end Row 2
                f'</div>',  # end panel
                unsafe_allow_html=True,
            )

        # ---------------- ENSEMBLE + SANDBOX ----------------
        left_col, right_col = st.columns(2)

        with left_col:
            st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
            st.markdown(f'<div class="rs-panel-title">🧠 Heterogeneous ML Ensemble Breakdown<span class="rs-panel-title-tag">{len(u_eval["individual_model_probs"])} models</span></div>', unsafe_allow_html=True)
            df_probs = pd.DataFrame(list(u_eval['individual_model_probs'].items()), columns=['Model', 'Probability'])
            df_probs['Probability (%)'] = df_probs['Probability'] * 100
            styled_probability_chart(df_probs, is_benign)
            st.markdown('</div>', unsafe_allow_html=True)

        with right_col:
            st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
            st.markdown('<div class="rs-panel-title">⚡ Physics-Informed Digital Twin Sandbox</div>', unsafe_allow_html=True)

            if p_ver:
                v_status = "🟢 CONSISTENT" if p_ver['is_physically_consistent'] else "🔴 LAW VIOLATION (FDIA DETECTED)"
                v_color  = COLOR_SAFE if p_ver['is_physically_consistent'] else COLOR_CRITICAL

                # Derived display values
                _vband_clr  = {'NORMAL': COLOR_SAFE, 'WARNING': COLOR_WARNING, 'CRITICAL': COLOR_CRITICAL}.get(
                               p_ver.get('voltage_band','NORMAL'), COLOR_MUTED)
                _freq_clr   = COLOR_CRITICAL if p_ver.get('frequency_outside_band') else COLOR_SAFE
                _brk_clr    = COLOR_CRITICAL if p_ver.get('breaker_tripped') else COLOR_SAFE
                _oc_clr     = COLOR_CRITICAL if p_ver.get('overcurrent_detected') else COLOR_SAFE
                _xfmr_clr   = COLOR_CRITICAL if p_ver.get('transformer_overloaded') else COLOR_TEXT
                _react_clr  = COLOR_WARNING  if p_ver.get('high_reactive_flag') else COLOR_TEXT
                _brk_causes = ', '.join(p_ver.get('breaker_trip_causes', [])) or 'None'

                md(f"""
                <div class="rs-card-label">Physical Law Consistency</div>
                <div style="font-family:'JetBrains Mono',monospace; color:{v_color}; font-weight:700; margin-bottom:0.75rem;">{v_status}</div>

                <!-- Row A: Power measurements -->
                <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:0.5rem; margin-bottom:0.55rem;">
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Active Power P</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{COLOR_TEXT};">{p_ver.get('active_power_mw',0):.1f} MW</div>
                    </div>
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Reactive Power Q</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{_react_clr};">{p_ver.get('reactive_power_mvar',0):.1f} MVAr</div>
                    </div>
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Apparent Power S</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{COLOR_TEXT};">{p_ver.get('apparent_power_mva',0):.2f} MVA</div>
                    </div>
                </div>

                <!-- Row B: Power-flow imbalance + PF + reactive ratio -->
                <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:0.5rem; margin-bottom:0.55rem;">
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Power-Flow Imbalance</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{COLOR_CRITICAL if p_ver.get('power_residual_pct',0)>8 else COLOR_TEXT};">{p_ver.get('power_residual_mva',0):.2f} MVA</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:{COLOR_MUTED};">{p_ver.get('power_residual_pct',0):.1f}% (thresh 8%)</div>
                    </div>
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Power Factor</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{COLOR_TEXT};">{p_ver.get('power_factor',1.0):.4f}</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:{COLOR_MUTED};">Q/P ratio: {p_ver.get('reactive_ratio',0):.2f}</div>
                    </div>
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Voltage</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{_vband_clr};">{p_ver.get('voltage_kv',0):.1f} kV</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:{_vband_clr};">Band: {p_ver.get('voltage_band','N/A')} ({p_ver.get('voltage_deviation_pct',0):.2f}% dev)</div>
                    </div>
                </div>

                <!-- Row C: Current, Frequency, Line/Transformer -->
                <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:0.5rem; margin-bottom:0.55rem;">
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Current / Overcurrent</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{_oc_clr};">{p_ver.get('current_amps',0):.0f} A</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:{COLOR_MUTED};">Rated: {p_ver.get('rated_current_amps',0):.0f} A · {'🔴 OVERCURRENT' if p_ver.get('overcurrent_detected') else '🟢 OK'}</div>
                    </div>
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Frequency</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{_freq_clr};">{p_ver.get('frequency_hz',50.0):.3f} Hz</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:{COLOR_MUTED};">Δ {p_ver.get('frequency_deviation_hz',0.0):+.3f} Hz (band ±0.5 Hz)</div>
                    </div>
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Line / Xfmr Loading</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{COLOR_CRITICAL if p_ver.get('line_loading_pct',0)>100 else COLOR_TEXT};">{p_ver.get('line_loading_pct',0):.1f}% / <span style="color:{_xfmr_clr};">{p_ver.get('transformer_loading_pct',0):.1f}%</span></div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:{COLOR_MUTED};">line cap / xfmr rated (trip@110%)</div>
                    </div>
                </div>

                <!-- Row D: Breaker status -->
                <div style="background:{COLOR_PANEL_ALT}; border:1px solid {_brk_clr}; border-radius:7px; padding:0.45rem 0.7rem; margin-bottom:0.8rem;">
                    <div class="rs-card-label" style="font-size:0.6rem;">Breaker Status</div>
                    <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{_brk_clr};">{p_ver.get('breaker_status','N/A')}</div>
                    <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:{COLOR_MUTED};">Trip causes: {_brk_causes}</div>
                </div>

                <hr style="margin:0.6rem 0;">
                <div class="rs-card-label">Simulated Mitigation Physical Impact</div>
                """)

                # Mitigation impact grid
                _ls_clr  = COLOR_CRITICAL if p_safe.get('line_stress_pct',0) > 100 else COLOR_TEXT
                _csc_clr = COLOR_SAFE if p_safe.get('cascading_failure_risk_pct',0)==0 else COLOR_CRITICAL
                _fq_clr2 = COLOR_CRITICAL if p_safe.get('freq_outside_band') else COLOR_SAFE
                _xt_clr2 = COLOR_CRITICAL if p_safe.get('transformer_overloaded') else COLOR_TEXT
                per_line = p_safe.get('per_line_loading', {})
                brk_stat = p_safe.get('breaker_statuses', {})

                md(f"""
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem; margin-bottom:0.55rem;">
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Target Node & Action</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.78rem; color:{COLOR_TEXT};">{p_safe.get('target_node','N/A')}</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:{COLOR_MUTED};">{p_safe.get('action_evaluated','N/A')}</div>
                    </div>
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Load Redistribution</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{COLOR_TEXT};">{p_safe.get('redistributed_load_mw',0):.1f} MW</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:{COLOR_MUTED};">{p_safe.get('per_line_load_mw',0):.1f} MW/line × {p_safe.get('n_lines_affected',3)} lines</div>
                    </div>
                </div>
                <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:0.5rem; margin-bottom:0.55rem;">
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Line Stress</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{_ls_clr};">{p_safe.get('line_stress_pct',0):.1f}%</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:{_csc_clr};">Cascade risk: {p_safe.get('cascading_failure_risk_pct',0):.1f}%</div>
                    </div>
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Transformer Load (post)</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{_xt_clr2};">{p_safe.get('transformer_loading_pct',0):.1f}%</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:{COLOR_MUTED};">{'⚠ OVERLOADED' if p_safe.get('transformer_overloaded') else 'within rating'}</div>
                    </div>
                    <div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.45rem 0.6rem;">
                        <div class="rs-card-label" style="font-size:0.6rem;">Freq Post-Event</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem; font-weight:700; color:{_fq_clr2};">{p_safe.get('freq_post_event_hz',50.0):.3f} Hz</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:{COLOR_MUTED};">Δ {p_safe.get('predicted_freq_delta_hz',0):+.3f} Hz</div>
                    </div>
                </div>
                """)

                # Per-line loading
                if per_line:
                    line_html = "".join([
                        f'<div style="background:{COLOR_PANEL_ALT}; border:1px solid {COLOR_BORDER}; border-radius:7px; padding:0.4rem 0.55rem;">'
                        f'<div class="rs-card-label" style="font-size:0.58rem;">{ln}</div>'
                        f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.82rem; font-weight:700; '
                        f'color:{COLOR_CRITICAL if lv>100 else (COLOR_WARNING if lv>80 else COLOR_TEXT)};">{lv:.1f}%</div>'
                        f'</div>'
                        for ln, lv in per_line.items()
                    ])
                    md(f"""
                    <div class="rs-card-label" style="margin-bottom:0.35rem;">Per-Line Loading (post-redistribution)</div>
                    <div style="display:grid; grid-template-columns:repeat({len(per_line)},1fr); gap:0.4rem; margin-bottom:0.55rem;">
                    {line_html}
                    </div>
                    """)

                # Breaker statuses per node
                if brk_stat:
                    brk_html = "".join([
                        f'<div style="background:{COLOR_PANEL_ALT}; border:1px solid {"#FF3B5C" if "OPEN" in bv or "ISOLATED" in bv else COLOR_BORDER}; border-radius:7px; padding:0.4rem 0.55rem;">'
                        f'<div class="rs-card-label" style="font-size:0.58rem;">{bn}</div>'
                        f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.78rem; font-weight:700; '
                        f'color:{"#FF3B5C" if "OPEN" in bv or "ISOLATED" in bv else COLOR_SAFE};">{bv}</div>'
                        f'</div>'
                        for bn, bv in brk_stat.items()
                    ])
                    md(f"""
                    <div class="rs-card-label" style="margin-bottom:0.35rem;">Breaker Status per Node</div>
                    <div style="display:grid; grid-template-columns:repeat({len(brk_stat)},1fr); gap:0.4rem; margin-bottom:0.8rem;">
                    {brk_html}
                    </div>
                    """)

            # SANDBOX VERDICT DISPLAY
            if not p_safe.get('is_physically_safe', True):
                md(f"""
                <div class="rs-card-label">Sandbox verdict</div>
                <div style="color:{COLOR_CRITICAL}; font-family:'JetBrains Mono',monospace; font-weight:700; font-size:1.0rem; margin-bottom:0.6rem;">🔴 {p_safe.get('physics_safety_verdict')}</div>
                <div style="color:{COLOR_WARNING}; font-size:0.85rem; background:rgba(255,59,92,0.1); padding:0.65rem; border-radius:6px; border:1px solid {COLOR_CRITICAL}; line-height:1.45;">
                    ⚠️ <b>PHYSICS ENGINE OVERRIDE:</b> ML model requested node isolation, but physics simulation proves this will overload transmission lines and cause an 87.5% risk of cascading regional blackout. Action BLOCKED.
                </div>
                """)
            elif is_benign:
                md(f"""
                <div class="rs-card-label">Sandbox verdict</div>
                <div style="color:{COLOR_SAFE}; font-family:'JetBrains Mono',monospace; font-weight:700; margin-bottom:0.6rem;">NORMAL_OPERATIONS_MAINTAINED</div>
                <div style="color:{COLOR_MUTED}; font-size:0.88rem;">No defensive patching required for clean telemetry.</div>
                """)
            else:
                md(f"""
                <div class="rs-card-label">Sandbox verdict</div>
                <div style="color:{COLOR_WARNING}; font-family:'JetBrains Mono',monospace; font-weight:700; margin-bottom:0.6rem;">{p_report['pre_validation_verdict']}</div>
                <div class="rs-card-label">Candidate defense action</div>
                <div style="color:{COLOR_TEXT}; font-size:0.88rem; margin-bottom:0.7rem; font-style:italic;">{p_report['action_description']}</div>
                <div class="rs-card-label">Pre-validated firewall rules</div>
                """)
                for rule in p_report['policy_rules']:
                    st.code(rule, language="bash")
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div style="height:1.4rem;"></div>', unsafe_allow_html=True)

        # ---------------- HUMAN-IN-THE-LOOP ----------------
        st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
        st.markdown('<div class="rs-panel-title">👤 Human-in-the-Loop Operations Control</div>', unsafe_allow_html=True)

        if not p_safe.get('is_physically_safe', True):
            st.error("🚨 **CRITICAL ALERT:** Physics Engine has overridden ML deployment recommendation. Deploying this patch will trigger a physical power grid blackout. Manual intervention required!")
            st.button("🛑 Block Deployment & Escalate to Grid Control Center", type="primary", use_container_width=True)
        elif is_benign:
            st.success("✅ Clean traffic confirmed. Log normal-operations verification to the compliance trail.")
            if st.button("📝 Log normal operations trail", type="primary"):
                audit_log = logger.log_event(attack, u_eval, p_report, human_approval_status='BENIGN_VERIFIED')
                st.success(f"Audit log saved with ID: `{audit_log['event_id']}`")
        else:
            st.warning("⚠️ European AI Act & NIS2 mandate: hardening actions require explicit human analyst authorization.")
            btn_col1, btn_col2, _ = st.columns([1, 1, 2])
            with btn_col1:
                if st.button("✅ Approve & deploy hardening", type="primary", use_container_width=True):
                    audit_log = logger.log_event(attack, u_eval, p_report, human_approval_status='APPROVED')
                    st.balloons()
                    st.success(f"🎉 Patch deployed to gateway. Compliance log ID: `{audit_log['event_id']}`")
            with btn_col2:
                if st.button("❌ Reject & escalate to field team", use_container_width=True):
                    audit_log = logger.log_event(attack, u_eval, p_report, human_approval_status='REJECTED')
                    st.error(f"🚫 Patch rejected by operator. Escalation logged with ID: `{audit_log['event_id']}`")
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div style="height:1.2rem;"></div>', unsafe_allow_html=True)

        # ---------------- TELEMETRY & COMPLIANCE TABS ----------------
        tab_telemetry, tab_compliance = st.tabs(["📄 Live Captured Telemetry", "🏛️ Regulatory Compliance Mapping"])

        with tab_telemetry:
            st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
            st.markdown('<div class="rs-card-label">Raw Telemetry Packet Payload</div>', unsafe_allow_html=True)
            st.json(attack)
            st.markdown('</div>', unsafe_allow_html=True)

        with tab_compliance:
            st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
            st.markdown('<div class="rs-card-label">Framework Standards Alignment</div>', unsafe_allow_html=True)
            compliance_badges(COMPLIANCE_MAP)
            st.markdown('<div style="height:0.8rem;"></div>', unsafe_allow_html=True)
            df_comp = pd.DataFrame(list(COMPLIANCE_MAP.items()), columns=['Framework Standard', 'Mapping Description'])
            st.dataframe(df_comp, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

    else:
        st.info("👈 Select an attack scenario or clean telemetry from the sidebar, then click 'Trigger Simulation' to start.")

# =========================================================================
# TAB 2: RESEARCH EXPERIMENTS & ABLATION STUDY
# =========================================================================
with main_tab2:
    st.markdown('<div class="rs-eyebrow">EMPIRICAL VALIDATION</div>', unsafe_allow_html=True)
    st.markdown("### 🔬 Comparative System Benchmark & Ablation Analysis")
    st.markdown("Evaluating AEGIS baseline against individual models and uncalibrated architectures.")

    # ── Experiment Controls ───────────────────────────────────────────────
    st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
    st.markdown('<div class="rs-panel-title">⚙️ Experiment Parameters</div>', unsafe_allow_html=True)
    exp_col1, exp_col2, exp_col3 = st.columns(3)
    with exp_col1:
        n_seeds = st.slider("Number of Random Seeds", min_value=1, max_value=15, value=5,
                            help="Zyada seeds = more statistically stable results. Graphs automatically update.")
    with exp_col2:
        n_samples = st.slider("Dataset Size (samples)", min_value=200, max_value=3000, value=1200, step=100,
                              help="Synthetic dataset ka size. Badha ke dekho accuracy kaise change hoti hai.")
    with exp_col3:
        attack_ratio = st.slider("Attack Ratio (%)", min_value=10, max_value=60, value=35,
                                 help="Dataset mein kitne % attack samples hon. Imbalance effect dekho.")
    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown('<div style="height:0.5rem;"></div>', unsafe_allow_html=True)

    # ── Run Button ────────────────────────────────────────────────────────
    run_col, status_col = st.columns([1, 3])
    with run_col:
        run_ablation = st.button("⚡ Run Ablation Experiment", type="primary", use_container_width=True)
    with status_col:
        status_placeholder = st.empty()

    # ── Chart + Table Placeholders ────────────────────────────────────────
    st.markdown('<div style="height:0.8rem;"></div>', unsafe_allow_html=True)
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
        st.markdown('<div class="rs-panel-title">📊 Detection Accuracy Comparison (%)</div>', unsafe_allow_html=True)
        acc_chart = st.empty()
        st.markdown('</div>', unsafe_allow_html=True)

    with chart_col2:
        st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
        st.markdown('<div class="rs-panel-title">🛡️ Defense Stability & Resilience Index (F1)</div>', unsafe_allow_html=True)
        f1_chart = st.empty()
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div style="height:0.8rem;"></div>', unsafe_allow_html=True)
    fpr_panel_open = st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
    st.markdown('<div class="rs-panel-title">📉 False Positive Rate Comparison (%)</div>', unsafe_allow_html=True)
    fpr_chart = st.empty()
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div style="height:0.8rem;"></div>', unsafe_allow_html=True)
    st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
    st.markdown('<div class="rs-panel-title">📋 Detailed Performance Metrics Table</div>', unsafe_allow_html=True)
    table_placeholder = st.empty()
    st.markdown('</div>', unsafe_allow_html=True)

    # ── Helper: render charts from df ─────────────────────────────────────
    def render_ablation_charts(df_res):
        # Accuracy bar chart
        fig_acc = px.bar(
            df_res,
            x="Model / Architecture",
            y="Accuracy (%)",
            color="Model / Architecture",
            text_auto='.2f',
            template="plotly_dark",
            color_discrete_sequence=px.colors.sequential.Plasma_r,
        )
        fig_acc.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            margin=dict(l=20, r=20, t=30, b=80),
            xaxis_tickangle=-20,
        )
        fig_acc.update_traces(textposition="outside")
        acc_chart.plotly_chart(fig_acc, use_container_width=True, key=f"acc_{n_seeds}_{n_samples}_{attack_ratio}")

        # F1 line chart
        fig_f1 = px.line(
            df_res,
            x="Model / Architecture",
            y="F1-Score",
            markers=True,
            template="plotly_dark",
            line_shape="spline",
        )
        fig_f1.update_traces(
            line=dict(color="#3B9EFF", width=3),
            marker=dict(size=10, color="#3B9EFF", line=dict(width=2, color="white"))
        )
        fig_f1.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=20, r=20, t=30, b=80),
            xaxis_tickangle=-20,
            yaxis=dict(range=[0, 1.05]),
        )
        f1_chart.plotly_chart(fig_f1, use_container_width=True, key=f"f1_{n_seeds}_{n_samples}_{attack_ratio}")

        # FPR bar chart
        fig_fpr = px.bar(
            df_res,
            x="Model / Architecture",
            y="False Positive Rate (%)",
            color="Model / Architecture",
            text_auto='.2f',
            template="plotly_dark",
            color_discrete_sequence=px.colors.sequential.Reds_r,
        )
        fig_fpr.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            margin=dict(l=20, r=20, t=30, b=80),
            xaxis_tickangle=-20,
        )
        fig_fpr.update_traces(textposition="outside")
        fpr_chart.plotly_chart(fig_fpr, use_container_width=True, key=f"fpr_{n_seeds}_{n_samples}_{attack_ratio}")

        # Table
        table_placeholder.dataframe(df_res, use_container_width=True)

    # ── On button click: re-run engine with current slider values ──────────
    if run_ablation:
        status_placeholder.info("⏳ Running multi-seed benchmark... please wait.")
        seeds = list(range(42, 42 + n_seeds))
        engine = AblationBenchmarkEngine(
            n_samples=n_samples,
            seeds=seeds,
            attack_weight=attack_ratio / 100.0,
        )
        ablation_results = engine.run_ablation_benchmark()
        st.session_state.ablation_results = ablation_results
        st.session_state.ablation_params = (n_seeds, n_samples, attack_ratio)
        status_placeholder.success(f"✅ Done — {n_seeds} seeds × {n_samples} samples × {attack_ratio}% attack ratio")

    # ── Re-render charts whenever session has data (persists across reruns) ─
    if 'ablation_results' in st.session_state:
        df_res = pd.DataFrame(st.session_state.ablation_results)
        # Ensure FPR column exists as numeric for chart
        if "False Positive Rate (%)" in df_res.columns:
            df_res["False Positive Rate (%)"] = df_res["False Positive Rate (%)"].apply(
                lambda x: float(str(x).split("±")[0].strip()) if isinstance(x, str) else float(x)
            )
        render_ablation_charts(df_res)

app_footer()

# =========================================================================
# TAB 3: GenAI ZERO-DAY LAB
# =========================================================================
with main_tab3:
    st.markdown('<div class="rs-eyebrow">SYNTHETIC THREAT INTELLIGENCE</div>', unsafe_allow_html=True)
    st.markdown("### 🧬 GenAI Zero-Day Attack Vector Generator")

    # ── Concept Explainer ────────────────────────────────────────────────
    with st.expander("📖 How does this work? (Concept Overview)", expanded=False):
        st.markdown("""
**Problem:** Traditional ML security models sirf wahi attacks pakad sakte hain jo unke training data mein pehle se maujood hain (historical attacks). Naye, unseen zero-day attacks inhe bypass kar jaate hain.

**GenAI Solution — Conditional Diffusion Model:**
Ye module ek deep learning **Conditional Diffusion Model** (PyTorch) use karta hai jo:
1. **Pure Gaussian Noise se shuru karta hai** — koi real attack data nahi, sirf random numbers.
2. **Iterative denoising** ke zariye realistic power grid SCADA telemetry patterns generate karta hai.
3. **Condition parameter** ke zariye aap AI ko instruction de sakte ho (jaise: severity = CRITICAL → overload wala attack generate karo).
4. **Physics Digital Twin** se verify karta hai ki generated payload real-world physical laws (Kirchhoff's Laws, Power Flow equations) ko violate karta hai ya nahi — tabhi use genuine zero-day anomaly maana jaata hai.

**Kyu zaruri hai?**
- Real power grid par actual attacks run karna dangerous + illegal hai.
- Purana data sirf known attacks cover karta hai.
- GenAI **trillions of novel attack vectors** artificially bana sakta hai.
- In synthetic samples par AEGIS apne detection models ko pre-train karta hai taaki real zero-day aane par system pehle se ready ho.
        """)

    st.markdown('<div style="height:0.8rem;"></div>', unsafe_allow_html=True)

    # ── Mode Toggle ──────────────────────────────────────────────────────
    input_mode = st.radio(
        "Input Mode",
        options=["🤖 Auto Generate (Diffusion Model)", "✏️ Manual Custom Case"],
        horizontal=True,
        help="Auto mode mein AI diffusion model values banata hai. Manual mode mein aap khud SCADA values enter kar sakte ho."
    )

    st.markdown('<div style="height:0.5rem;"></div>', unsafe_allow_html=True)

    # ── Controls ─────────────────────────────────────────────────────────
    st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
    st.markdown('<div class="rs-panel-title">⚙️ Generation Parameters</div>', unsafe_allow_html=True)

    if input_mode == "🤖 Auto Generate (Diffusion Model)":
        ctrl_col1, ctrl_col2, ctrl_col3 = st.columns(3)
        with ctrl_col1:
            severity_label = st.selectbox(
                "Attack Severity Condition",
                options=["LOW (0.25)", "MEDIUM (0.5)", "HIGH (0.75)", "CRITICAL (1.0)"],
                index=3,
                help="Diffusion model ko ye condition pass hoti hai — higher value = more aggressive anomaly."
            )
            severity_map = {"LOW (0.25)": 0.25, "MEDIUM (0.5)": 0.5, "HIGH (0.75)": 0.75, "CRITICAL (1.0)": 1.0}
            scenario_condition = severity_map[severity_label]
        with ctrl_col2:
            num_samples = st.slider("Number of Payloads to Generate", min_value=1, max_value=10, value=1,
                                    help="Ek baar mein kitne synthetic zero-day payloads generate karein.")
        with ctrl_col3:
            force_physics_violation = st.checkbox(
                "Force Physics Violation Check",
                value=True,
                help="Agar checked hai toh Physics Digital Twin se verify karega ki payload physical laws violate karta hai ya nahi."
            )

    else:  # Manual Custom Case
        st.markdown("**📋 Custom SCADA Telemetry Values**")
        st.caption("Apni marzi ki values enter karo — Physics Twin check karega ki ye physically valid hai ya anomaly.")

        man_col1, man_col2 = st.columns(2)
        with man_col1:
            st.markdown("**⚡ Physical Telemetry**")
            custom_voltage   = st.number_input("Voltage (kV)",          min_value=50.0,  max_value=300.0, value=138.0, step=0.5,
                                               help="Normal range: 131–145 kV. Isse bahar = suspicious.")
            custom_current   = st.number_input("Current (Amps)",        min_value=0.0,   max_value=2000.0, value=500.0, step=10.0,
                                               help="Normal: ~500A. 900A+ = overload.")
            custom_active_pw = st.number_input("Active Power (MW)",     min_value=0.0,   max_value=1000.0, value=300.0, step=5.0,
                                               help="Normal: 100–400 MW.")
            custom_react_pw  = st.number_input("Reactive Power (MVAr)", min_value=0.0,   max_value=500.0,  value=45.0,  step=1.0,
                                               help="Normal: 20–60 MVAr.")

        with man_col2:
            st.markdown("**🌐 Network Features**")
            custom_flow_dur    = st.number_input("Flow Duration (s)",       min_value=0.0,   max_value=2000.0, value=400.0, step=10.0)
            custom_fwd_pkts    = st.number_input("Total Fwd Packets",       min_value=0,     max_value=5000,   value=700,   step=10)
            custom_bwd_pkts    = st.number_input("Total Bwd Packets",       min_value=0,     max_value=2000,   value=200,   step=10)
            custom_pkt_len     = st.number_input("Packet Length Mean",      min_value=0.0,   max_value=5000.0, value=1200.0,step=10.0)
            custom_failed_log  = st.number_input("Failed Login Attempts",   min_value=0,     max_value=50,     value=3,     step=1)
            custom_api_resp    = st.number_input("API Response Time (ms)",  min_value=0.0,   max_value=5000.0, value=250.0, step=10.0)

            st.markdown("**🚨 Attack Flags**")
            flag_col1, flag_col2 = st.columns(2)
            custom_unauth_port = flag_col1.checkbox("Unauthorized Port Access", value=True)
            custom_priv_esc    = flag_col2.checkbox("Privilege Escalation",     value=True)

        custom_target = st.text_input("Target Node", value="Transformer_Substation_04",
                                      help="Konsa grid node attack kar raha hai.")
        num_samples = 1
        force_physics_violation = False  # Manual mode mein actual physics calculation use hogi

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown('<div style="height:0.8rem;"></div>', unsafe_allow_html=True)

    # ── Generate Button ───────────────────────────────────────────────────
    btn_label = "🧪 Generate Synthetic Zero-Day Attack Payload(s)" if input_mode == "🤖 Auto Generate (Diffusion Model)" else "🔬 Run Custom Case Through Physics Twin"
    if st.button(btn_label, type="primary"):
        with st.spinner("Processing..."):
            generated_payloads = []
            physics_results = []

            if input_mode == "🤖 Auto Generate (Diffusion Model)":
                for i in range(num_samples):
                    payload = diffusion_gen.generate_zero_day_payload(scenario_condition=scenario_condition)
                    generated_payloads.append(payload)
                    phys_result = physics_twin.verify_physical_laws(
                        payload["phys_telemetry"],
                        scenario_key="FDIA_PHYSICS_FAILURE" if force_physics_violation else None
                    )
                    physics_results.append(phys_result)

            else:  # Manual mode
                # Derive a severity score from the manual physics inputs
                # (voltage deviation + current overload act as a proxy condition)
                voltage_dev = abs(custom_voltage - 138.0) / 138.0
                current_dev = max(0.0, (custom_current - 500.0) / 500.0)
                manual_condition = float(np.clip((voltage_dev + current_dev) / 2.0, 0.0, 1.0))

                manual_payload = {
                    "scenario_key": "MANUAL_CUSTOM_CASE",
                    "mitre_id": "CUSTOM",
                    "attack_name": "User-Defined Custom Test Case",
                    "target_node": custom_target,
                    "severity": "CUSTOM",
                    "voltage_kv": round(custom_voltage, 2),
                    "current_amps": round(custom_current, 2),
                    "active_power_mw": round(custom_active_pw, 2),
                    "reactive_power_mvar": round(custom_react_pw, 2),
                    "phys_telemetry": {
                        "voltage_kv": round(custom_voltage, 2),
                        "current_amps": round(custom_current, 2),
                        "active_power_mw": round(custom_active_pw, 2),
                        "reactive_power_mvar": round(custom_react_pw, 2),
                    },
                    "network_features": {
                        "flow_duration": round(custom_flow_dur, 2),
                        "total_fwd_packets": int(custom_fwd_pkts),
                        "total_bwd_packets": int(custom_bwd_pkts),
                        "packet_length_mean": round(custom_pkt_len, 2),
                        "unauthorized_port_access": int(custom_unauth_port),
                        "failed_login_attempts": int(custom_failed_log),
                        "privilege_escalation_flag": int(custom_priv_esc),
                        "api_response_time_ms": round(custom_api_resp, 2),
                    },
                    "batadal_features": diffusion_gen._build_batadal_features(
                        manual_condition, custom_voltage, custom_current, custom_active_pw
                    ),
                }
                generated_payloads.append(manual_payload)
                phys_result = physics_twin.verify_physical_laws(manual_payload["phys_telemetry"])
                physics_results.append(phys_result)

            st.session_state["zd_payloads"] = generated_payloads
            st.session_state["zd_physics"] = physics_results

    # ── Results ───────────────────────────────────────────────────────────
    if "zd_payloads" in st.session_state:
        payloads      = st.session_state["zd_payloads"]
        phys_list     = st.session_state["zd_physics"]
        zd_mode       = st.session_state.get("zd_mode", "auto")

        st.success(f"✅ {len(payloads)} Payload(s) processed through full pipeline!")
        st.markdown('<div style="height:0.5rem;"></div>', unsafe_allow_html=True)

        for idx, (payload, phys) in enumerate(zip(payloads, phys_list)):

            # ── Run ML Ensemble + Uncertainty Engine on network features ──
            net = payload["network_features"]
            if ACTIVE_DATASET == 'batadal':
                df_net = pd.DataFrame([payload["batadal_features"]])[BATADAL_FEATURE_COLUMNS]
            else:
                df_net = pd.DataFrame([{
                    "flow_duration":           net["flow_duration"],
                    "total_fwd_packets":       net["total_fwd_packets"],
                    "total_bwd_packets":       net["total_bwd_packets"],
                    "packet_length_mean":      net["packet_length_mean"],
                    "failed_login_attempts":   net["failed_login_attempts"],
                    "privilege_escalation_flag": net["privilege_escalation_flag"],
                    "api_response_time_ms":    net["api_response_time_ms"],
                    "unauthorized_port_access":net["unauthorized_port_access"],
                }])
            ml_probs   = blue_ensemble.predict_probabilities(df_net)
            u_eval     = uncertainty_engine.evaluate_uncertainty(ml_probs)
            threat_score = u_eval["composite_threat_score"]
            is_benign    = threat_score < 0.25

            expander_icon = "🟢" if is_benign else "🔴"
            with st.expander(
                f"{expander_icon} Payload #{idx + 1} — {payload['attack_name']}  |  "
                f"Threat: {threat_score*100:.1f}%  |  Target: {payload['target_node']}",
                expanded=(idx == 0)
            ):
                # ── Verdict Banner ──────────────────────────────────────
                verdict_banner(is_benign, payload.get("attack_name"))
                st.markdown('<div style="height:0.8rem;"></div>', unsafe_allow_html=True)

                # ── KPI Row ─────────────────────────────────────────────
                kpi1, kpi2, kpi3, kpi4 = st.columns(4)
                with kpi1:
                    kpi_card("Composite Threat Score",
                             f"{threat_score*100:.1f}%",
                             "✓ Safe / Clean" if is_benign else "⚠ Critical Threat",
                             "safe" if is_benign else "critical", icon="◆")
                with kpi2:
                    kpi_card("Epistemic Variance (σ²)",
                             f"{u_eval['epistemic_uncertainty_variance']:.6f}",
                             u_eval["decision_verdict"],
                             "info", icon="≈")
                with kpi3:
                    kpi_card("Ensemble Decision",
                             "PASS" if is_benign else "BLOCK",
                             u_eval["recommended_action"],
                             "safe" if is_benign else "critical", icon="⛨")
                with kpi4:
                    phys_ok = phys.get("is_physically_consistent", True)
                    kpi_card("Physics Twin",
                             "✅ CONSISTENT" if phys_ok else "🔴 VIOLATION",
                             f"Residual: {phys['power_residual_pct']}%",
                             "safe" if phys_ok else "critical", icon="⚡")

                st.markdown('<div style="height:1rem;"></div>', unsafe_allow_html=True)

                # ── Integrated Safety Report ─────────────────────────────
                zd_patch_stub = {
                    "action_description": "DYNAMIC_MICRO_SEGMENTATION",
                    "security_gain_pct":  85.0,
                    "grid_disruption_pct": 0.5,
                }
                zd_safety_stub = physics_twin.simulate_mitigation_safety(
                    target_node=payload.get("target_node", "Grid_Node"),
                    action_type="DYNAMIC_MICRO_SEGMENTATION",
                    current_load_mw=payload["phys_telemetry"].get("active_power_mw", 110.0),
                )
                zd_i_report = integrated_report_engine.generate_report(
                    ml_eval      = u_eval,
                    phys_verify  = phys,
                    phys_safety  = zd_safety_stub,
                    patch_report = zd_patch_stub,
                )
                zd_cri    = zd_i_report.get("combined_risk_index", 0.0)
                zd_verdict= zd_i_report.get("final_verdict", "UNKNOWN")
                zd_color  = {
                    "CRITICAL_CONFIRMED": COLOR_CRITICAL,
                    "HIGH_THREAT":        COLOR_CRITICAL,
                    "AMBIGUOUS_MONITOR":  COLOR_WARNING,
                    "BENIGN_CLEAR":       COLOR_SAFE,
                }.get(zd_verdict, COLOR_MUTED)
                gate_note = (
                    f'<br><span style="color:{COLOR_WARNING}; font-size:0.78rem;">'
                    f'⚠ Physics Safety Gate triggered</span>'
                ) if zd_i_report.get("physics_gate_triggered") else ""

                md(f"""
                <div class="rs-panel" style="border-color:{zd_color}; margin-bottom:1rem;">
                    <div class="rs-panel-title">🔬 Integrated Safety Report
                        <span class="rs-panel-title-tag">ML + Physics Fusion</span>
                    </div>
                    <div style="display:flex; gap:1.5rem; flex-wrap:wrap; align-items:center;">
                        <div>
                            <div class="rs-card-label">Combined Risk Index (CRI)</div>
                            <div style="font-family:'JetBrains Mono',monospace; font-size:1.8rem;
                                        font-weight:800; color:{zd_color};">{zd_cri:.4f}</div>
                            <div style="font-family:'JetBrains Mono',monospace; font-size:0.7rem;
                                        color:{COLOR_MUTED};">0.50×ML + 0.35×Physics + 0.15×KCL</div>
                        </div>
                        <div style="flex:1; min-width:160px;">
                            <div class="rs-card-label">Final Verdict</div>
                            <div style="font-family:'JetBrains Mono',monospace; font-size:1rem;
                                        font-weight:700; color:{zd_color};">{zd_verdict}</div>
                            <div style="font-family:'JetBrains Mono',monospace; font-size:0.75rem;
                                        color:{COLOR_MUTED};">
                                Confidence: <b style="color:{COLOR_TEXT};">{zd_i_report.get('confidence_pct',0)}%</b>
                                &nbsp;·&nbsp;
                                Human Approval:
                                <b style="color:{'#FF9500' if zd_i_report.get('human_approval_required') else COLOR_SAFE};">
                                {'REQUIRED' if zd_i_report.get('human_approval_required') else 'NOT REQUIRED'}</b>
                            </div>
                        </div>
                        <div style="flex:1; min-width:160px;">
                            <div class="rs-card-label">Recommended Action</div>
                            <div style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;
                                        color:{COLOR_TEXT};">
                                {zd_i_report.get('recommended_action','N/A')}{gate_note}
                            </div>
                        </div>
                        <div>
                            <div class="rs-card-label">Signal Breakdown</div>
                            <div style="font-family:'JetBrains Mono',monospace; font-size:0.75rem;
                                        color:{COLOR_MUTED}; line-height:1.8;">
                                ML (45%):&nbsp;&nbsp;&nbsp;
                                    <b style="color:{COLOR_TEXT};">{zd_i_report.get('ml_threat_score',0)*100:.1f}%</b><br>
                                Physics (30%):
                                    <b style="color:{COLOR_TEXT};">{zd_i_report.get('physics_anomaly_score',0)*100:.1f}%</b><br>
                                Overcurrent (10%):
                                    <b style="color:{'#FF3B5C' if zd_i_report.get('overcurrent_detected') else COLOR_SAFE};">
                                    {'YES' if zd_i_report.get('overcurrent_detected') else 'NO'}</b><br>
                                Freq (10%):&nbsp;
                                    <b style="color:{'#FF3B5C' if zd_i_report.get('frequency_outside_band') else COLOR_SAFE};">
                                    {zd_i_report.get('frequency_hz',50.0):.3f} Hz</b><br>
                                Xfmr (5%):&nbsp;
                                    <b style="color:{'#FF3B5C' if zd_i_report.get('transformer_overloaded_live') else COLOR_TEXT};">
                                    {zd_i_report.get('transformer_loading_pct_live',0):.1f}%</b>
                            </div>
                        </div>
                    </div>
                </div>
                """)

                st.markdown('<div style="height:0.5rem;"></div>', unsafe_allow_html=True)

                # ── ML Ensemble + Physics Twin side by side ─────────────
                ml_col, phys_col = st.columns(2)

                with ml_col:
                    st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
                    st.markdown(
                        f'<div class="rs-panel-title">🧠 Heterogeneous ML Ensemble'
                        f'<span class="rs-panel-title-tag">{len(ml_probs)} models</span></div>',
                        unsafe_allow_html=True
                    )
                    df_probs = pd.DataFrame(
                        list(ml_probs.items()), columns=["Model", "Probability"]
                    )
                    df_probs["Probability (%)"] = df_probs["Probability"] * 100
                    styled_probability_chart(df_probs, is_benign)
                    st.markdown('</div>', unsafe_allow_html=True)

                with phys_col:
                    st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
                    st.markdown('<div class="rs-panel-title">⚡ Physics-Informed Digital Twin Verdict</div>',
                                unsafe_allow_html=True)
                    anomaly_detected = phys.get("physical_anomaly_detected", False)
                    if anomaly_detected:
                        st.error("🚨 PHYSICAL LAW VIOLATION — FDIA / Zero-Day Anomaly Confirmed")
                    else:
                        st.success("✅ Physically Consistent — Normal Grid State")

                    # Power metrics row
                    r1c1, r1c2, r1c3 = st.columns(3)
                    r1c1.metric("Active P (MW)",   f"{phys.get('active_power_mw',0):.1f}")
                    r1c2.metric("Reactive Q (MVAr)",f"{phys.get('reactive_power_mvar',0):.1f}",
                                delta="⚠ High" if phys.get('high_reactive_flag') else "OK",
                                delta_color="inverse" if phys.get('high_reactive_flag') else "off")
                    r1c3.metric("Apparent S (MVA)", f"{phys.get('apparent_power_mva',0):.2f}")

                    st.markdown('<div style="height:0.3rem;"></div>', unsafe_allow_html=True)

                    r2c1, r2c2, r2c3 = st.columns(3)
                    r2c1.metric("Power Residual",
                                f"{phys['power_residual_mva']} MVA",
                                delta=f"{phys['power_residual_pct']}% (thresh 8%)",
                                delta_color="inverse")
                    r2c2.metric("Power Factor",    f"{phys.get('power_factor',1.0):.4f}",
                                delta=f"Q/P={phys.get('reactive_ratio',0):.2f}",
                                delta_color="off")
                    r2c3.metric("Voltage",
                                f"{phys.get('voltage_kv',0):.1f} kV",
                                delta=f"{phys.get('voltage_band','N/A')} ({phys.get('voltage_deviation_pct',0):.2f}% dev)",
                                delta_color="inverse" if phys.get('voltage_band') != 'NORMAL' else "off")

                    st.markdown('<div style="height:0.3rem;"></div>', unsafe_allow_html=True)

                    r3c1, r3c2, r3c3 = st.columns(3)
                    r3c1.metric("Frequency",
                                f"{phys.get('frequency_hz',50.0):.3f} Hz",
                                delta=f"Δ{phys.get('frequency_deviation_hz',0):+.3f} Hz",
                                delta_color="inverse" if phys.get('frequency_outside_band') else "off")
                    r3c2.metric("Line / Xfmr Load",
                                f"{phys.get('line_loading_pct',0):.1f}% / {phys.get('transformer_loading_pct',0):.1f}%",
                                delta="⚠ XFMR OVERLOAD" if phys.get('transformer_overloaded') else "within rating",
                                delta_color="inverse" if phys.get('transformer_overloaded') else "off")
                    r3c3.metric("Breaker",
                                "TRIPPED" if phys.get('breaker_tripped') else "CLOSED",
                                delta=', '.join(phys.get('breaker_trip_causes',[])) or 'None',
                                delta_color="inverse" if phys.get('breaker_tripped') else "off")

                    st.markdown('</div>', unsafe_allow_html=True)

                # ── Network Features ─────────────────────────────────────
                st.markdown('<div style="height:0.5rem;"></div>', unsafe_allow_html=True)
                st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
                st.markdown('<div class="rs-panel-title">🌐 Network Feature Vector (ML Model Input)</div>',
                            unsafe_allow_html=True)
                nf1 = st.columns(4)
                nf1[0].metric("Flow Duration (s)",    net["flow_duration"])
                nf1[1].metric("Fwd Packets",          net["total_fwd_packets"])
                nf1[2].metric("Bwd Packets",          net["total_bwd_packets"])
                nf1[3].metric("Pkt Length Mean",      net["packet_length_mean"])
                nf2 = st.columns(4)
                nf2[0].metric("Unauth Port Access",   "🔴 YES" if net["unauthorized_port_access"] else "🟢 NO")
                nf2[1].metric("Failed Logins",        net["failed_login_attempts"])
                nf2[2].metric("Privilege Escalation", "🔴 YES" if net["privilege_escalation_flag"] else "🟢 NO")
                nf2[3].metric("API Response (ms)",    net["api_response_time_ms"])
                st.markdown('</div>', unsafe_allow_html=True)

                # ── Raw JSON ─────────────────────────────────────────────
                with st.expander("🗂️ View Raw JSON Payload"):
                    st.json(payload)

        # ── Batch Summary Table (only when >1 payload) ───────────────────
        if len(payloads) > 1:
            st.markdown('<div style="height:0.8rem;"></div>', unsafe_allow_html=True)
            st.markdown('<div class="rs-panel">', unsafe_allow_html=True)
            st.markdown('<div class="rs-panel-title">📋 Batch Summary — All Payloads</div>',
                        unsafe_allow_html=True)
            summary_rows = []
            for i, (p, ph) in enumerate(zip(payloads, phys_list)):
                net_s  = p["network_features"]
                df_s   = pd.DataFrame([{
                    "flow_duration": net_s["flow_duration"],
                    "total_fwd_packets": net_s["total_fwd_packets"],
                    "total_bwd_packets": net_s["total_bwd_packets"],
                    "packet_length_mean": net_s["packet_length_mean"],
                    "failed_login_attempts": net_s["failed_login_attempts"],
                    "privilege_escalation_flag": net_s["privilege_escalation_flag"],
                    "api_response_time_ms": net_s["api_response_time_ms"],
                    "unauthorized_port_access": net_s["unauthorized_port_access"],
                }])
                probs_s = blue_ensemble.predict_probabilities(df_s)
                u_s     = uncertainty_engine.evaluate_uncertainty(probs_s)
                summary_rows.append({
                    "Payload #":             i + 1,
                    "Voltage (kV)":          p["phys_telemetry"]["voltage_kv"],
                    "Active Power (MW)":     p["phys_telemetry"]["active_power_mw"],
                    "Threat Score (%)":      round(u_s["composite_threat_score"] * 100, 1),
                    "Ensemble Decision":     u_s["decision_verdict"],
                    "Power Residual (%)":    ph["power_residual_pct"],
                    "Physics Anomaly":       "🔴 YES" if ph["physical_anomaly_detected"] else "🟢 NO",
                    "Priv Escalation":       "YES" if net_s["privilege_escalation_flag"] else "NO",
                    "Unauth Port":           "YES" if net_s["unauthorized_port_access"] else "NO",
                })
            st.dataframe(pd.DataFrame(summary_rows), use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)