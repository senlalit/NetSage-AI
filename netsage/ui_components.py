"""Reusable UI Components and Design System for NetSage AI (NetSage Sentinel).

Provides high-contrast NOC/SOC styling, technical typography (Inter + JetBrains Mono),
semantic status badges, telemetry cards, and layout helpers for Streamlit.
"""

from typing import Any, Dict, List, Optional
import streamlit as st
from netsage.models import AIDiagnosisOutput, DeterministicFinding

# Custom CSS for NOC/SOC Technical Operations Center Aesthetic
NOC_CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

/* Global Font & Color Palette */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    color: #DAE2FD;
}

/* Backgrounds */
.stApp {
    background-color: #0B1326;
}

/* Sidebar Styling */
section[data-testid="stSidebar"] {
    background-color: #060E20;
    border-right: 1px solid #1E293B;
}

/* Typography Overrides */
h1, h2, h3, h4, h5, h6 {
    font-family: 'Inter', sans-serif;
    font-weight: 700;
    color: #F8FAFC;
    letter-spacing: -0.02em;
}

code, pre, .stCode, .stCodeBlock, span[data-testid="stCodeBlock"] {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background-color: #060E20;
    border-bottom: 1px solid #334155;
    padding: 6px 10px;
    gap: 8px;
}

.stTabs [data-baseweb="tab"] {
    font-family: 'Inter', sans-serif;
    font-weight: 600;
    font-size: 0.92rem;
    color: #94A3B8;
    padding: 8px 18px;
    border-radius: 4px;
    background-color: transparent;
    border: 1px solid transparent;
}

.stTabs [aria-selected="true"] {
    background-color: #171F33 !important;
    color: #38BDF8 !important;
    border: 1px solid #38BDF8 !important;
}

/* Metric Containers */
div[data-testid="stMetric"] {
    background-color: #171F33;
    border: 1px solid #334155;
    border-radius: 4px;
    padding: 12px 16px;
}
div[data-testid="stMetricLabel"] {
    color: #94A3B8;
    font-size: 0.8rem;
    text-transform: uppercase;
    font-weight: 700;
    letter-spacing: 0.05em;
}
div[data-testid="stMetricValue"] {
    color: #38BDF8;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
}

/* Buttons */
.stButton > button {
    font-family: 'Inter', sans-serif;
    font-weight: 600;
    border-radius: 4px;
    border: 1px solid #334155;
    transition: all 0.15s ease-in-out;
}
.stButton > button:hover {
    border-color: #38BDF8;
    color: #38BDF8;
}

/* Primary Button */
.stButton > button[kind="primary"] {
    background-color: #38BDF8;
    color: #060E20;
    border: 1px solid #38BDF8;
    font-weight: 700;
}
.stButton > button[kind="primary"]:hover {
    background-color: #7BD0FF;
    border-color: #7BD0FF;
    color: #001E2C;
}

/* Dataframe & Tables */
div[data-testid="stDataFrame"] {
    border: 1px solid #334155;
    border-radius: 4px;
}

/* Custom Cards */
.noc-card {
    background-color: #171F33;
    border: 1px solid #334155;
    border-radius: 4px;
    padding: 16px;
    margin-bottom: 16px;
}

.noc-card-header {
    font-family: 'Inter', sans-serif;
    font-size: 0.82rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #94A3B8;
    margin-bottom: 10px;
    border-bottom: 1px solid #1E293B;
    padding-bottom: 6px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

/* Status Badges */
.badge-critical {
    background-color: #93000A;
    color: #FFDAD6;
    padding: 3px 8px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 700;
    border: 1px solid #FF5449;
    display: inline-block;
}

.badge-warning {
    background-color: #613B00;
    color: #FFDDB8;
    padding: 3px 8px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 700;
    border: 1px solid #F1A02B;
    display: inline-block;
}

.badge-success {
    background-color: #064E3B;
    color: #D1FAE5;
    padding: 3px 8px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 700;
    border: 1px solid #10B981;
    display: inline-block;
}

.badge-info {
    background-color: #004965;
    color: #C4E7FF;
    padding: 3px 8px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 700;
    border: 1px solid #38BDF8;
    display: inline-block;
}

.badge-layer {
    background-color: #2D3449;
    color: #DAE2FD;
    padding: 3px 8px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 700;
    border: 1px solid #475569;
    display: inline-block;
}

/* System Status Dot */
.status-dot-online {
    height: 8px;
    width: 8px;
    background-color: #10B981;
    border-radius: 50%;
    display: inline-block;
    margin-right: 6px;
    box-shadow: 0 0 6px #10B981;
}

/* Terminal Look */
.noc-terminal {
    background-color: #060E20;
    border: 1px solid #334155;
    border-radius: 4px;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    color: #38BDF8;
    overflow-x: auto;
}
</style>
"""


def apply_custom_css() -> None:
    """Inject centralized NOC/SOC CSS into Streamlit page."""
    st.markdown(NOC_CUSTOM_CSS, unsafe_allow_html=True)


def render_sidebar_status() -> None:
    """Render the sidebar system status indicators and security seal."""
    from netsage.system_health import get_system_status
    status = get_system_status()

    with st.sidebar:
        st.markdown(
            """
            <div style="margin-bottom: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: baseline;">
                    <h2 style="margin: 0; color: #38BDF8; font-size: 1.4rem; letter-spacing: -0.02em;">NETSAGE AI</h2>
                    <span style="background-color: #171F33; border: 1px solid #334155; color: #94A3B8; font-size: 0.7rem; font-family: 'JetBrains Mono'; padding: 2px 6px; border-radius: 3px;">v1.0.0</span>
                </div>
                <div style="color: #94A3B8; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; font-family: 'JetBrains Mono';">Diagnostic Intelligence</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        data_info = f"{status['data_layer']['status']} ({status['data_layer']['cases_loaded']} Cases)"
        det_info = f"{status['deterministic_engine']['rules_registered']} Rules Active"
        ai_info = "Gemini API & Offline" if status['ai_engine']['gemini_configured'] else "Offline Deterministic"
        audit_info = f"Append-Only ({status['audit_ledger']['total_records']} Records)"

        st.markdown(
            f"""
            <div style="background-color: #171F33; border: 1px solid #334155; border-radius: 4px; padding: 12px; margin-bottom: 20px;">
                <div style="font-size: 0.72rem; font-weight: 700; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 8px; font-family: 'JetBrains Mono';">
                    SYSTEM STATUS (v1.0.0)
                </div>
                <div style="font-size: 0.8rem; margin-bottom: 6px;"><span class="status-dot-online"></span><strong>Data Layer:</strong> {data_info}</div>
                <div style="font-size: 0.8rem; margin-bottom: 6px;"><span class="status-dot-online"></span><strong>Deterministic:</strong> {det_info}</div>
                <div style="font-size: 0.8rem; margin-bottom: 6px;"><span class="status-dot-online"></span><strong>AI Engine:</strong> {ai_info}</div>
                <div style="font-size: 0.8rem;"><span class="status-dot-online"></span><strong>Audit Ledger:</strong> {audit_info}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            """
            <div style="background-color: #060E20; border: 1px solid #1E293B; border-left: 3px solid #10B981; border-radius: 4px; padding: 10px 12px; margin-bottom: 20px;">
                <div style="color: #34D399; font-size: 0.75rem; font-weight: 700; font-family: 'JetBrains Mono'; text-transform: uppercase;">
                    🔒 READ-ONLY MODE
                </div>
                <div style="color: #94A3B8; font-size: 0.72rem; margin-top: 4px;">
                    Advisory and diagnostic assistance only. No commands are dispatched to network devices.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_advisory_banner() -> None:
    """Render prominent advisory-only security and safety guardrail banner."""
    st.markdown(
        """
        <div style="background-color: #171F33; border: 1px solid #334155; border-left: 4px solid #38BDF8; padding: 12px 18px; border-radius: 4px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <strong style="color: #38BDF8; font-size: 0.95rem; font-family: 'JetBrains Mono';">🛡️ ADVISORY-ONLY & READ-ONLY SAFETY SYSTEM</strong>
                <span class="badge-info">AIR-GAPPED TELEMETRY</span>
            </div>
            <div style="color: #CBD5E1; font-size: 0.85rem; margin-top: 4px;">
                NetSage AI generates evidence-grounded root cause analyses and verification recommendations.
                <strong>No automated network deployment, SSH/Telnet sessions, or device changes are executed.</strong>
                All remediation steps require mandatory human review and manual engineer authorization.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_severity_badge(severity: str) -> str:
    """Return HTML string for semantic severity badge."""
    sev = severity.strip().capitalize()
    if sev == "High":
        return f'<span class="badge-critical">HIGH CRITICALITY</span>'
    elif sev == "Medium":
        return f'<span class="badge-warning">MEDIUM SEVERITY</span>'
    else:
        return f'<span class="badge-info">LOW SEVERITY</span>'


def render_decision_badge(decision: str) -> str:
    """Return HTML string for review decision badge."""
    dec = decision.strip().upper()
    if dec == "ACCEPT":
        return '<span class="badge-success">APPROVED / ACCEPTED</span>'
    elif dec == "EDIT":
        return '<span class="badge-warning">EDITED / CORRECTED</span>'
    elif dec == "REJECT":
        return '<span class="badge-critical">PROPOSAL REJECTED</span>'
    return f'<span class="badge-info">{dec}</span>'


def render_hitl_gate_banner() -> None:
    """Render the prominent Human Review Gate banner."""
    st.markdown(
        """
        <div style="background-color: #1E293B; border: 1px solid #F59E0B; border-radius: 4px; padding: 12px 16px; margin: 16px 0;">
            <div style="color: #FBBF24; font-size: 0.9rem; font-weight: 700; font-family: 'JetBrains Mono';">
                ⚠️ HUMAN REVIEW REQUIRED
            </div>
            <div style="color: #E2E8F0; font-size: 0.85rem; margin-top: 4px;">
                The AI diagnostic proposal is strictly advisory and cannot be approved until a qualified network engineer reviews and validates the findings.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_diff_view(diff: Dict[str, Dict[str, Any]]) -> None:
    """Render a structured visual representation of the human edit diff."""
    if not diff:
        st.info("No field modifications detected between original AI proposal and edited version.")
        return

    st.markdown("##### 📝 Structured Field Differences")
    for field_name, change in diff.items():
        st.markdown(
            f"""
            <div style="background-color: #0F172A; border: 1px solid #334155; border-radius: 4px; padding: 10px 14px; margin-bottom: 8px;">
                <div style="font-family: 'JetBrains Mono'; font-weight: 700; color: #38BDF8; font-size: 0.85rem; text-transform: uppercase;">
                    Field: {field_name}
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 6px;">
                    <div style="background-color: #1E1B2E; border: 1px solid #6B21A8; padding: 8px; border-radius: 3px; font-size: 0.8rem;">
                        <span style="color: #D8B4FE; font-weight: 700; font-family: 'JetBrains Mono';">ORIGINAL (AI):</span><br/>
                        <code>{change.get('before')}</code>
                    </div>
                    <div style="background-color: #06281E; border: 1px solid #047857; padding: 8px; border-radius: 3px; font-size: 0.8rem;">
                        <span style="color: #6EE7B7; font-weight: 700; font-family: 'JetBrains Mono';">HUMAN EDITED:</span><br/>
                        <code>{change.get('after')}</code>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
