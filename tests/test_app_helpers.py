"""Unit tests for NetSage AI Streamlit application helper workflows."""

import pytest
from netsage.case_loader import load_cases, get_case
from netsage.deterministic_engine import run_deterministic_checks
from netsage.ai_engine import AIEngine, OfflineDeterministicProvider
from netsage.models import AIDiagnosisOutput, HumanReview, NetworkCase
from netsage.audit_manager import AuditManager, compute_edit_diff


def test_case_explorer_filters() -> None:
    """Verify filtering logic used in the Case Explorer UI."""
    cases = load_cases()
    assert len(cases) == 30

    # Filter High severity
    high_cases = [c for c in cases if c.severity == "High"]
    assert len(high_cases) == 16

    # Filter Medium severity
    med_cases = [c for c in cases if c.severity == "Medium"]
    assert len(med_cases) == 11

    # Filter Low severity
    low_cases = [c for c in cases if c.severity == "Low"]
    assert len(low_cases) == 3

    # Filter Layer 2
    l2_cases = [c for c in cases if c.osi_layer == "Layer 2"]
    assert len(l2_cases) == 9

    # Filter OSPF concept
    ospf_cases = [c for c in cases if c.concept_tag == "OSPF"]
    assert len(ospf_cases) == 3


def test_custom_sandbox_case_creation_and_diagnosis() -> None:
    """Verify custom sandbox input processing through deterministic rules and AI engine."""
    custom_case = NetworkCase(
        case_id="CUSTOM-SANDBOX-001",
        symptom="PC cannot ping router gateway",
        topology_note="PC on Fa0/1; Gateway on Gi0/0.10",
        show_outputs="GigabitEthernet0/0.10 is administratively down line protocol is down",
        expected_fault="Custom Simulation",
        osi_layer="Layer 3",
        concept_tag="Sandbox",
        severity="High",
    )

    det_res = run_deterministic_checks(custom_case)
    assert len(det_res.findings) >= 1
    assert det_res.findings[0].rule_id == "INTERFACE_ADMIN_DOWN"

    ai_engine = AIEngine(provider=OfflineDeterministicProvider())
    diagnosis = ai_engine.diagnose(custom_case, det_res)

    assert isinstance(diagnosis, AIDiagnosisOutput)
    assert "administratively down" in diagnosis.evidence[0]
    assert diagnosis.confidence >= 0.90


def test_audit_analytics_summary_format() -> None:
    """Verify metrics calculation for Analytics Dashboard tab."""
    cases = load_cases()
    manager = AuditManager()
    metrics = manager.calculate_metrics(cases=cases)

    assert "total_reviewed" in metrics
    assert "accepted_count" in metrics
    assert "edited_count" in metrics
    assert "rejected_count" in metrics
    assert "ai_correction_rate" in metrics
    assert "acceptance_rate" in metrics
    assert "avg_ai_confidence" in metrics
    assert "count_by_osi_layer" in metrics
    assert "count_by_severity" in metrics
