"""NetSage AI: Cisco & Packet Tracer Network Troubleshooting Assistant.

NOC/SOC Operations Console providing:
1. Case Explorer (30 Authoritative benchmark cases with ground-truth isolation)
2. Diagnostic & HITL Console (Deterministic telemetry parsing + Grounded AI reasoning + Human Review Gate)
3. Audit & Governance Analytics (Compliance metrics, edit diffs, immutable audit trail)
4. Custom Cisco CLI Diagnostic Sandbox (Air-gapped, read-only simulation playground)
"""

import os
from typing import Any, Dict, List, Optional
import pandas as pd
import streamlit as st

from netsage.ai_engine import (
    AIEngine,
    GeminiProvider,
    OfflineDeterministicProvider,
    UngroundedEvidenceError,
)
from netsage.audit_manager import AuditManager, compute_edit_diff, review_diagnosis
from netsage.case_loader import CaseLoader, get_case, load_cases
from netsage.deterministic_engine import DeterministicEngine, run_deterministic_checks
from netsage.models import (
    AIDiagnosisOutput,
    DeterministicFinding,
    DeterministicResult,
    HumanReview,
    NetworkCase,
    VALID_OSI_LAYERS,
)
from netsage.ui_components import (
    apply_custom_css,
    render_advisory_banner,
    render_decision_badge,
    render_diff_view,
    render_hitl_gate_banner,
    render_severity_badge,
    render_sidebar_status,
)

# Page configuration
st.set_page_config(
    page_title="NetSage AI | NOC Diagnostic Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize global audit manager
AUDIT_MANAGER = AuditManager()


def init_session_state() -> None:
    """Initialize Streamlit session state variables."""
    if "selected_case_id" not in st.session_state:
        st.session_state.selected_case_id = "NET-001"
    if "current_det_result" not in st.session_state:
        st.session_state.current_det_result = None
    if "current_ai_diagnosis" not in st.session_state:
        st.session_state.current_ai_diagnosis = None
    if "last_review_message" not in st.session_state:
        st.session_state.last_review_message = None
    if "sandbox_case" not in st.session_state:
        st.session_state.sandbox_case = None
    if "sandbox_det_result" not in st.session_state:
        st.session_state.sandbox_det_result = None
    if "sandbox_ai_diagnosis" not in st.session_state:
        st.session_state.sandbox_ai_diagnosis = None


# ============================================================================
# View 1: Case Explorer
# ============================================================================


def render_case_explorer(all_cases: List[NetworkCase]) -> None:
    """Render the Case Explorer view with search, filter, and telemetry details."""
    st.markdown("### 📋 Benchmark Case Explorer")
    st.caption("Inspect and filter all 30 authoritative Cisco / Packet Tracer troubleshooting benchmark cases.")

    # High-level dataset summary metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Cases", len(all_cases))
    m2.metric("High Criticality", sum(1 for c in all_cases if c.severity == "High"))
    m3.metric("Medium Severity", sum(1 for c in all_cases if c.severity == "Medium"))
    m4.metric("Low Severity", sum(1 for c in all_cases if c.severity == "Low"))

    st.markdown("<br/>", unsafe_allow_html=True)

    # Filter controls
    col1, col2, col3 = st.columns(3)
    with col1:
        severities = ["All"] + sorted(list(set(c.severity for c in all_cases)))
        selected_sev = st.selectbox("Filter by Severity", severities)
    with col2:
        layers = ["All"] + sorted(list(set(c.osi_layer for c in all_cases)))
        selected_layer = st.selectbox("Filter by OSI Layer", layers)
    with col3:
        concepts = ["All"] + sorted(list(set(c.concept_tag for c in all_cases)))
        selected_concept = st.selectbox("Filter by Concept Tag", concepts)

    # Apply filters
    filtered_cases = all_cases
    if selected_sev != "All":
        filtered_cases = [c for c in filtered_cases if c.severity == selected_sev]
    if selected_layer != "All":
        filtered_cases = [c for c in filtered_cases if c.osi_layer == selected_layer]
    if selected_concept != "All":
        filtered_cases = [c for c in filtered_cases if c.concept_tag == selected_concept]

    st.markdown(f"**Showing {len(filtered_cases)} of {len(all_cases)} Cases**")

    # Table summary
    table_data = [
        {
            "Case ID": c.case_id,
            "Symptom": c.symptom,
            "Severity": c.severity,
            "OSI Layer": c.osi_layer,
            "Concept Tag": c.concept_tag,
        }
        for c in filtered_cases
    ]
    st.dataframe(pd.DataFrame(table_data), use_container_width=True, hide_index=True)

    st.markdown("---")

    # Detailed Case Viewer
    case_ids = [c.case_id for c in filtered_cases] if filtered_cases else [c.case_id for c in all_cases]
    selected_id = st.selectbox("Select Case to Inspect Telemetry", case_ids, index=0 if case_ids else 0)

    selected_case = get_case(selected_id)
    if selected_case:
        c1, c2 = st.columns([2, 1])
        with c1:
            st.markdown(
                f"""
                <div class="noc-card">
                    <div class="noc-card-header">
                        <span>CASE IDENTIFIER: {selected_case.case_id}</span>
                        <span>{render_severity_badge(selected_case.severity)}</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #94A3B8; font-weight: 700; text-transform: uppercase;">Observable Symptom:</div>
                    <div style="font-size: 0.95rem; color: #F8FAFC; margin: 4px 0 12px 0;">{selected_case.symptom}</div>
                    
                    <div style="font-size: 0.85rem; color: #94A3B8; font-weight: 700; text-transform: uppercase;">Topology & Interface Context:</div>
                    <div style="font-size: 0.9rem; color: #CBD5E1; font-family: 'JetBrains Mono'; margin: 4px 0 12px 0;">{selected_case.topology_note}</div>
                    
                    <div style="font-size: 0.85rem; color: #94A3B8; font-weight: 700; text-transform: uppercase; margin-bottom: 6px;">Cisco Show-Command Telemetry:</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.code(selected_case.show_outputs, language="text")

        with c2:
            st.markdown(
                f"""
                <div class="noc-card">
                    <div class="noc-card-header">
                        <span>BENCHMARK ATTRIBUTES</span>
                    </div>
                    <div style="margin-bottom: 8px;">
                        <span style="color: #94A3B8; font-size: 0.8rem;">OSI Layer:</span><br/>
                        <span class="badge-layer">{selected_case.osi_layer}</span>
                    </div>
                    <div style="margin-bottom: 8px;">
                        <span style="color: #94A3B8; font-size: 0.8rem;">Concept Tag:</span><br/>
                        <span class="badge-info">{selected_case.concept_tag}</span>
                    </div>
                    <div style="margin-bottom: 12px;">
                        <span style="color: #94A3B8; font-size: 0.8rem;">Severity Level:</span><br/>
                        {render_severity_badge(selected_case.severity)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown(
                f"""
                <div style="background-color: #171F33; border: 1px solid #334155; border-left: 3px solid #64748B; border-radius: 4px; padding: 12px; margin-bottom: 16px;">
                    <div style="font-size: 0.75rem; font-weight: 700; color: #94A3B8; text-transform: uppercase; font-family: 'JetBrains Mono';">
                        BENCHMARK GROUND TRUTH FAULT
                    </div>
                    <div style="color: #F1F5F9; font-size: 0.88rem; font-style: italic; margin-top: 4px;">
                        "{selected_case.expected_fault}"
                    </div>
                    <div style="color: #64748B; font-size: 0.72rem; margin-top: 6px;">
                        *Evaluation ground truth label only — strictly isolated from AI reasoning input.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if st.button("🚀 Load Case into Diagnostic Console", use_container_width=True, type="primary"):
                st.session_state.selected_case_id = selected_case.case_id
                st.session_state.current_det_result = None
                st.session_state.current_ai_diagnosis = None
                st.success(f"Case {selected_case.case_id} loaded into Diagnostic Console tab!")


# ============================================================================
# View 2: Diagnostic & HITL Console
# ============================================================================


def render_diagnostic_console(all_cases: List[NetworkCase]) -> None:
    """Render the Diagnostic & Human-in-the-Loop review station."""
    st.markdown("### 🔍 Diagnostic & HITL Operations Console")
    st.caption("Execute deterministic telemetry validation and grounded AI root-cause analysis with mandatory human authorization.")

    case_ids = [c.case_id for c in all_cases]
    current_idx = case_ids.index(st.session_state.selected_case_id) if st.session_state.selected_case_id in case_ids else 0

    col_sel, col_prov = st.columns([2, 1])
    with col_sel:
        chosen_id = st.selectbox("Select Active Troubleshooting Case", case_ids, index=current_idx)
        if chosen_id != st.session_state.selected_case_id:
            st.session_state.selected_case_id = chosen_id
            st.session_state.current_det_result = None
            st.session_state.current_ai_diagnosis = None

    active_case = get_case(st.session_state.selected_case_id)
    if not active_case:
        st.error("Selected case could not be loaded.")
        return

    with col_prov:
        has_gemini_key = bool(os.getenv("GEMINI_API_KEY"))
        provider_options = ["Offline Deterministic Engine (Zero-API, Fast)"]
        if has_gemini_key:
            provider_options.append("Google Gemini Live API")
        provider_choice = st.radio("AI Diagnostic Engine", provider_options)

    # Active Case Header Card
    st.markdown(
        f"""
        <div class="noc-card" style="margin-top: 10px;">
            <div class="noc-card-header">
                <span>ACTIVE CASE: <strong style="color: #38BDF8;">{active_case.case_id}</strong> ({active_case.concept_tag})</span>
                <div>
                    <span class="badge-layer">{active_case.osi_layer}</span>
                    {render_severity_badge(active_case.severity)}
                </div>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                <div>
                    <span style="color: #94A3B8; font-size: 0.8rem; font-weight: 700; text-transform: uppercase;">Symptom:</span>
                    <div style="color: #F8FAFC; font-size: 0.92rem; margin-top: 2px;">{active_case.symptom}</div>
                </div>
                <div>
                    <span style="color: #94A3B8; font-size: 0.8rem; font-weight: 700; text-transform: uppercase;">Topology:</span>
                    <div style="color: #CBD5E1; font-size: 0.88rem; font-family: 'JetBrains Mono'; margin-top: 2px;">{active_case.topology_note}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Run Diagnosis Trigger
    if st.button("⚡ Execute Telemetry Checks & AI Diagnosis", type="primary", use_container_width=True):
        # 1. Deterministic Engine
        det_engine = DeterministicEngine()
        det_res = det_engine.analyze_case(active_case)
        st.session_state.current_det_result = det_res

        # 2. AI Diagnostic Engine
        if provider_choice.startswith("Google Gemini") and has_gemini_key:
            provider = GeminiProvider()
        else:
            provider = OfflineDeterministicProvider()

        ai_engine = AIEngine(provider=provider)
        try:
            ai_diag = ai_engine.diagnose(active_case, det_res)
            st.session_state.current_ai_diagnosis = ai_diag
            st.session_state.last_review_message = None
        except UngroundedEvidenceError as e:
            st.error(f"Grounding Safety Violation: {e}")
            st.session_state.current_ai_diagnosis = None
        except Exception as e:
            st.error(f"Diagnostic Error: {e}")
            st.session_state.current_ai_diagnosis = None

    # Render Results & HITL Review
    if st.session_state.current_det_result and st.session_state.current_ai_diagnosis:
        det_res: DeterministicResult = st.session_state.current_det_result
        ai_diag: AIDiagnosisOutput = st.session_state.current_ai_diagnosis

        st.markdown("---")
        col_det, col_ai = st.columns(2)

        # 1. Telemetry & Deterministic Findings
        with col_det:
            st.markdown(
                f"""
                <div class="noc-card-header">
                    <span>1. CISCO SHOW OUTPUT (SOURCE TELEMETRY)</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.code(active_case.show_outputs, language="text")

            st.markdown(
                f"""
                <div class="noc-card-header" style="margin-top: 14px;">
                    <span>DETERMINISTIC FINDINGS ({len(det_res.findings)} ANOMALIES DETECTED / {det_res.rules_checked} RULES CHECKED)</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if det_res.findings:
                for idx, finding in enumerate(det_res.findings, 1):
                    badge_class = "badge-critical" if finding.status == "ERROR" else "badge-warning"
                    st.markdown(
                        f"""
                        <div style="background-color: #060E20; border: 1px solid #334155; border-radius: 4px; padding: 10px; margin-bottom: 8px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <strong style="color: #38BDF8; font-family: 'JetBrains Mono'; font-size: 0.85rem;">[{idx}] {finding.rule_id}</strong>
                                <span class="{badge_class}">{finding.status}</span>
                            </div>
                            <div style="color: #94A3B8; font-size: 0.78rem;">Evidence Snippet: <code style="color: #F87171;">{finding.evidence}</code></div>
                            <div style="color: #E2E8F0; font-size: 0.85rem; margin-top: 4px;">{finding.message}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.info("No hard anomaly signatures detected by deterministic rules.")

        # 2. AI Diagnostic Proposal
        with col_ai:
            st.markdown(
                f"""
                <div class="noc-card-header">
                    <span>2. AI DIAGNOSTIC PROPOSAL (ADVISORY)</span>
                    <span class="badge-info">GROUNDED SYNTHESIS</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown(
                f"""
                <div class="noc-card">
                    <div style="color: #94A3B8; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; font-family: 'JetBrains Mono';">Root Cause Analysis:</div>
                    <h4 style="color: #38BDF8; margin: 4px 0 12px 0;">{ai_diag.root_cause}</h4>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;">
                        <div>
                            <span style="color: #94A3B8; font-size: 0.75rem; font-family: 'JetBrains Mono'; text-transform: uppercase;">Assigned Layer:</span><br/>
                            <span class="badge-layer">{ai_diag.osi_layer}</span>
                        </div>
                        <div>
                            <span style="color: #94A3B8; font-size: 0.75rem; font-family: 'JetBrains Mono'; text-transform: uppercase;">Confidence:</span><br/>
                            <strong style="color: #38BDF8; font-family: 'JetBrains Mono'; font-size: 1.1rem;">{ai_diag.confidence * 100:.1f}%</strong>
                        </div>
                    </div>
                    
                    <div style="color: #94A3B8; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; font-family: 'JetBrains Mono'; margin-bottom: 4px;">Grounded Telemetry Evidence:</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            for ev in ai_diag.evidence:
                st.markdown(f"- `{ev}`")

            st.markdown("**Recommended Verification Command:**")
            st.code(ai_diag.next_command, language="bash")

            st.markdown("**Recommended Sequential Fix Steps (Advisory):**")
            st.code("\n".join(ai_diag.fix_steps), language="bash")

        st.markdown("---")

        # 3. Mandatory Human-in-the-Loop Review Station
        st.markdown("### 3. 🧑‍💻 Mandatory Human-in-the-Loop Review Station")
        render_hitl_gate_banner()

        action_tab1, action_tab2, action_tab3 = st.tabs(["✅ Accept Proposal", "✏️ Edit & Correct Proposal", "❌ Reject Proposal"])

        # ACCEPT TAB
        with action_tab1:
            st.markdown("Approve the AI diagnosis proposal as verified and ready for standard change-window execution.")
            accept_notes = st.text_input("Reviewer Notes (Optional)", key="accept_notes", placeholder="e.g., Verified against network diagram; approved for execution.")
            if st.button("✅ Confirm Acceptance", type="primary"):
                review = HumanReview(decision="ACCEPT", reviewer_notes=accept_notes)
                record = AUDIT_MANAGER.review_diagnosis(active_case, det_res, ai_diag, review)
                st.success(f"Diagnosis ACCEPTED and recorded in Audit Ledger! Audit ID: **{record.audit_id}**")
                st.session_state.last_review_message = f"Accepted record {record.audit_id}"

        # EDIT TAB
        with action_tab2:
            st.markdown("Modify any diagnostic attributes. Human edits remain strictly subject to schema and evidence grounding validation.")
            with st.form("edit_diagnosis_form"):
                e_root_cause = st.text_input("Root Cause", value=ai_diag.root_cause)
                e_osi_layer = st.selectbox("OSI Layer", sorted(list(VALID_OSI_LAYERS)), index=sorted(list(VALID_OSI_LAYERS)).index(ai_diag.osi_layer) if ai_diag.osi_layer in VALID_OSI_LAYERS else 0)
                e_confidence = st.slider("Confidence", min_value=0.0, max_value=1.0, value=float(ai_diag.confidence), step=0.01)
                e_evidence_str = st.text_area("Evidence (one item per line)", value="\n".join(ai_diag.evidence))
                e_next_cmd = st.text_input("Next Verification Command", value=ai_diag.next_command)
                e_fix_steps_str = st.text_area("Fix Steps (one command per line)", value="\n".join(ai_diag.fix_steps))
                e_notes = st.text_input("Reason for Human Correction / Notes", placeholder="e.g. Corrected interface name and adjusted confidence.")

                submit_edit = st.form_submit_button("✏️ Submit Corrected Diagnosis")

            if submit_edit:
                try:
                    e_evidence = [line.strip() for line in e_evidence_str.split("\n") if line.strip()]
                    e_fix_steps = [line.strip() for line in e_fix_steps_str.split("\n") if line.strip()]

                    edited_diag = AIDiagnosisOutput(
                        root_cause=e_root_cause,
                        osi_layer=e_osi_layer,
                        confidence=e_confidence,
                        evidence=e_evidence,
                        next_command=e_next_cmd,
                        fix_steps=e_fix_steps,
                    )

                    review = HumanReview(
                        decision="EDIT",
                        edited_diagnosis=edited_diag,
                        reviewer_notes=e_notes,
                    )

                    record = AUDIT_MANAGER.review_diagnosis(active_case, det_res, ai_diag, review)
                    st.success(f"Edited diagnosis approved and recorded! Audit ID: **{record.audit_id}**")
                    if record.edit_diff:
                        render_diff_view(record.edit_diff)
                except UngroundedEvidenceError as e:
                    st.error(f"Grounding Safety Rejection: {e}")
                except Exception as e:
                    st.error(f"Validation Error: {e}")

        # REJECT TAB
        with action_tab3:
            st.markdown("Reject the proposed diagnosis. Rejection reason is required for governance tracking.")
            rejection_reason = st.text_area("Rejection Reason (Mandatory)", placeholder="e.g. Telemetry does not support the root cause hypothesis.")
            reject_notes = st.text_input("Additional Notes", key="reject_notes")

            if st.button("❌ Confirm Rejection", type="secondary"):
                if not rejection_reason.strip():
                    st.error("Rejection reason is mandatory.")
                else:
                    review = HumanReview(
                        decision="REJECT",
                        rejection_reason=rejection_reason,
                        reviewer_notes=reject_notes,
                    )
                    record = AUDIT_MANAGER.review_diagnosis(active_case, det_res, ai_diag, review)
                    st.warning(f"Proposal REJECTED and logged in Audit Ledger! Audit ID: **{record.audit_id}**")


# ============================================================================
# View 3: Audit & Analytics
# ============================================================================


def render_audit_analytics(all_cases: List[NetworkCase]) -> None:
    """Render the Responsible-AI Audit Ledger and governance metrics."""
    st.markdown("### 📊 Responsible-AI Audit Ledger & Governance Analytics")
    st.caption("Immutable append-only audit trail recording every AI diagnosis, human decision, and edit diff.")

    records = AUDIT_MANAGER.get_all_records()
    metrics = AUDIT_MANAGER.calculate_metrics(cases=all_cases)

    # Top KPI Cards
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("Total Reviews", metrics["total_reviewed"])
    k2.metric("Accepted", f"{metrics['accepted_count']} ({metrics['acceptance_rate']*100:.1f}%)")
    k3.metric("AI Corrected", f"{metrics['edited_count']} ({metrics['ai_correction_rate']*100:.1f}%)")
    k4.metric("Rejected", f"{metrics['rejected_count']} ({metrics['rejection_rate']*100:.1f}%)")
    k5.metric("Avg AI Conf.", f"{metrics['avg_ai_confidence']*100:.1f}%")
    k6.metric("Avg Final Conf.", f"{metrics['avg_final_confidence']*100:.1f}%")

    st.markdown("---")

    # Visual Distributions
    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        st.markdown("#### Decisions by OSI Layer")
        if metrics["count_by_osi_layer"]:
            df_osi = pd.DataFrame(
                list(metrics["count_by_osi_layer"].items()),
                columns=["OSI Layer", "Count"],
            ).set_index("OSI Layer")
            st.bar_chart(df_osi)
        else:
            st.info("No reviews recorded yet to generate OSI distribution.")

    with col_chart2:
        st.markdown("#### Reviews by Case Severity")
        if metrics["count_by_severity"]:
            df_sev = pd.DataFrame(
                list(metrics["count_by_severity"].items()),
                columns=["Severity", "Count"],
            ).set_index("Severity")
            st.bar_chart(df_sev)
        else:
            st.info("No reviews recorded yet to generate severity distribution.")

    st.markdown("---")

    # Audit Records Table & Inspector
    st.markdown(f"#### Audit Trail Ledger ({len(records)} Records)")
    if records:
        table_rows = []
        for r in reversed(records):
            table_rows.append(
                {
                    "Audit ID": r.audit_id,
                    "Case ID": r.case_id,
                    "Timestamp": r.timestamp[:19],
                    "Decision": r.review_decision,
                    "AI Corrected": "Yes" if r.was_ai_corrected else "No",
                    "AI Confidence": f"{r.ai_diagnosis.confidence*100:.1f}%",
                    "Final Confidence": f"{r.final_approved_output.confidence*100:.1f}%" if r.final_approved_output else "N/A",
                }
            )
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

        st.markdown("##### 🔎 Inspect Audit Record Details")
        rec_ids = [r.audit_id for r in reversed(records)]
        inspect_id = st.selectbox("Select Audit ID to inspect", rec_ids)
        inspect_record = AUDIT_MANAGER.get_record(inspect_id)

        if inspect_record:
            i1, i2 = st.columns(2)
            with i1:
                st.markdown(
                    f"""
                    <div class="noc-card">
                        <div class="noc-card-header">
                            <span>AUDIT IDENTIFIER: {inspect_record.audit_id}</span>
                            <span>{render_decision_badge(inspect_record.review_decision)}</span>
                        </div>
                        <div style="font-size: 0.8rem; color: #94A3B8;">Case ID: <strong style="color: #38BDF8;">{inspect_record.case_id}</strong></div>
                        <div style="font-size: 0.8rem; color: #94A3B8;">Timestamp: <span style="font-family: 'JetBrains Mono';">{inspect_record.timestamp}</span></div>
                        <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 4px;">Reviewer Notes: <span style="color: #F8FAFC;">{inspect_record.reviewer_notes or 'None'}</span></div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                if inspect_record.rejection_reason:
                    st.error(f"**Rejection Reason:** {inspect_record.rejection_reason}")

                st.markdown("**Original AI Diagnosis Proposal:**")
                st.json(inspect_record.ai_diagnosis.model_dump())

            with i2:
                if inspect_record.final_approved_output:
                    st.markdown("**Final Approved Output:**")
                    st.json(inspect_record.final_approved_output.model_dump())
                else:
                    st.warning("No approved output (Proposal Rejected).")

                if inspect_record.edit_diff:
                    render_diff_view(inspect_record.edit_diff)
    else:
        st.info("The audit ledger is currently empty. Run a diagnosis and record a human review decision to populate it.")


# ============================================================================
# View 4: Custom Cisco CLI Diagnostic Sandbox
# ============================================================================


def render_custom_sandbox() -> None:
    """Render the Custom Cisco CLI Diagnostic Sandbox."""
    st.markdown("### 🧪 Custom Cisco CLI Diagnostic Sandbox")
    st.caption("Evaluate arbitrary Cisco IOS show-commands in a safe, read-only simulation environment.")

    st.markdown(
        """
        <div style="background-color: #060E20; border: 1px solid #F59E0B; border-left: 4px solid #F59E0B; padding: 10px 14px; border-radius: 4px; margin-bottom: 16px;">
            <div style="color: #FBBF24; font-weight: 700; font-family: 'JetBrains Mono';">⚠️ SIMULATION & ADVISORY ENVIRONMENT</div>
            <div style="color: #94A3B8; font-size: 0.85rem; margin-top: 4px;">
                Enter simulated Cisco IOS telemetry snippets. NetSage AI runs deterministic rules and grounded AI reasoning. No live network connections are opened.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("custom_sandbox_form"):
        c_id = st.text_input("Custom Case Reference ID", value="CUSTOM-001")
        c_symptom = st.text_input("Observable Symptom", placeholder="e.g. PC1 cannot reach default gateway 192.168.10.1")
        c_topo = st.text_input("Topology Notes", placeholder="e.g. PC1 on Fa0/1 VLAN 10; Router Gateway on Gi0/0.10")
        c_show = st.text_area("Cisco Show Command Outputs", placeholder="e.g. GigabitEthernet0/0.10 is administratively down line protocol is down", height=150)

        analyze_btn = st.form_submit_button("🧪 Analyze Custom Telemetry", type="primary")

    if analyze_btn:
        if not c_symptom.strip() or not c_show.strip():
            st.error("Both Symptom and Cisco Show Command Outputs are required.")
        elif len(c_show) > 50000:
            st.error("Cisco show output payload exceeds maximum allowed size (50,000 characters).")
        elif len(c_symptom) > 1000:
            st.error("Symptom text exceeds maximum allowed length (1,000 characters).")
        elif len(c_topo) > 2000:
            st.error("Topology note exceeds maximum allowed length (2,000 characters).")
        else:
            custom_case = NetworkCase(
                case_id=c_id.strip() or "CUSTOM-001",
                symptom=c_symptom.strip(),
                topology_note=c_topo.strip() or "Custom sandbox topology",
                show_outputs=c_show.strip(),
                expected_fault="Custom Simulation",
                osi_layer="Layer 3",
                concept_tag="Sandbox",
                severity="Medium",
            )

            det_engine = DeterministicEngine()
            det_res = det_engine.analyze_case(custom_case)

            ai_engine = AIEngine()
            try:
                ai_diag = ai_engine.diagnose(custom_case, det_res)
                st.session_state.sandbox_case = custom_case
                st.session_state.sandbox_det_result = det_res
                st.session_state.sandbox_ai_diagnosis = ai_diag
            except UngroundedEvidenceError as e:
                st.error(f"Grounding Safety Error: {e}")
                st.session_state.sandbox_ai_diagnosis = None
            except Exception as e:
                st.error(f"Diagnostic Error: {e}")
                st.session_state.sandbox_ai_diagnosis = None

    if st.session_state.sandbox_case and st.session_state.sandbox_det_result and st.session_state.sandbox_ai_diagnosis:
        s_case: NetworkCase = st.session_state.sandbox_case
        s_det: DeterministicResult = st.session_state.sandbox_det_result
        s_diag: AIDiagnosisOutput = st.session_state.sandbox_ai_diagnosis

        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Deterministic Telemetry Findings")
            if s_det.findings:
                for f in s_det.findings:
                    st.markdown(f"- **{f.rule_id}** (`{f.status}`): {f.message} (Evidence: `{f.evidence}`)")
            else:
                st.info("No matching deterministic rule signatures found.")

        with col2:
            st.markdown("#### AI Diagnostic Proposal")
            st.markdown(f"**Root Cause:** {s_diag.root_cause}")
            st.markdown(f"**OSI Layer:** `{s_diag.osi_layer}` | **Confidence:** `{s_diag.confidence*100:.1f}%`")
            st.markdown("**Evidence:**")
            for ev in s_diag.evidence:
                st.markdown(f"- `{ev}`")
            st.markdown("**Next Verification Command:**")
            st.code(s_diag.next_command, language="bash")
            st.markdown("**Remediation Steps:**")
            st.code("\n".join(s_diag.fix_steps), language="bash")


# ============================================================================
# Main App Entrypoint
# ============================================================================


def main() -> None:
    """Main application layout and navigation orchestrator."""
    init_session_state()
    apply_custom_css()
    render_sidebar_status()

    # Ingest benchmark cases through case loader service
    try:
        all_cases = load_cases()
    except Exception as e:
        st.error(f"Fatal Error loading cases.csv: {e}")
        return

    # Header and advisory banner
    render_advisory_banner()

    # Navigation Tabs
    tab1, tab2, tab3, tab4 = st.tabs(
        [
            "📋 1. Case Explorer",
            "🔍 2. Diagnostic & HITL Console",
            "📊 3. Audit & Analytics",
            "🧪 4. Custom CLI Sandbox",
        ]
    )

    with tab1:
        render_case_explorer(all_cases)

    with tab2:
        render_diagnostic_console(all_cases)

    with tab3:
        render_audit_analytics(all_cases)

    with tab4:
        render_custom_sandbox()


if __name__ == "__main__":
    main()
