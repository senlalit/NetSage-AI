"""Error handling and resilience tests for NetSage AI."""

import json
from pathlib import Path
import pytest

from netsage.ai_engine import AIEngine, UngroundedEvidenceError
from netsage.audit_manager import AuditManager
from netsage.deterministic_engine import DeterministicEngine
from netsage.models import AIDiagnosisOutput, HumanReview, NetworkCase


def test_corrupted_audit_ledger_recovers_gracefully(tmp_path) -> None:
    """Verify that a corrupted JSON audit ledger does not crash AuditManager."""
    corrupted_file = tmp_path / "corrupted_audit.json"
    corrupted_file.write_text("{ this is NOT valid JSON :::", encoding="utf-8")

    manager = AuditManager(ledger_path=corrupted_file)
    records = manager.get_all_records()
    assert records == []


def test_atomic_audit_write_preserves_file(tmp_path) -> None:
    """Verify that atomic write correctly persists audit records."""
    audit_file = tmp_path / "atomic_audit.json"
    manager = AuditManager(ledger_path=audit_file)

    case = NetworkCase(
        case_id="NET-001",
        symptom="PC1 cannot reach Server1",
        topology_note="Sub-interface Gi0/0.10",
        show_outputs="GigabitEthernet0/0.10 is administratively down",
        expected_fault="Sub-interface down",
        osi_layer="Layer 3",
        concept_tag="Routing",
        severity="High",
    )
    det_res = DeterministicEngine().analyze_case(case)
    ai_diag = AIEngine().diagnose(case, det_res)
    review = HumanReview(decision="ACCEPT", reviewer_notes="Testing atomic write")

    record = manager.review_diagnosis(case, det_res, ai_diag, review)
    assert audit_file.exists()
    assert record.audit_id in audit_file.read_text(encoding="utf-8")


def test_rejection_without_mandatory_reason_fails() -> None:
    """Verify that REJECT decision without reason raises ValueError or ValidationError."""
    with pytest.raises(ValueError):
        HumanReview(decision="REJECT", rejection_reason="")


def test_ungrounded_edit_during_review_raises_error() -> None:
    """Verify that edited diagnosis with fabricated evidence is rejected during review."""
    manager = AuditManager()
    case = NetworkCase(
        case_id="NET-001",
        symptom="PC1 cannot reach Server1",
        topology_note="Sub-interface Gi0/0.10",
        show_outputs="GigabitEthernet0/0.10 is administratively down",
        expected_fault="Sub-interface down",
        osi_layer="Layer 3",
        concept_tag="Routing",
        severity="High",
    )
    det_res = DeterministicEngine().analyze_case(case)
    ai_diag = AIEngine().diagnose(case, det_res)

    fabricated_edit = AIDiagnosisOutput(
        root_cause="Hardware backplane fire",
        osi_layer="Layer 1",
        confidence=0.99,
        evidence=["Catastrophic electrical short on ASIC chip 0"],
        next_command="show chassis",
        fix_steps=["replace chassis"],
    )

    with pytest.raises(UngroundedEvidenceError):
        manager.review_diagnosis(
            case,
            det_res,
            ai_diag,
            HumanReview(decision="EDIT", edited_diagnosis=fabricated_edit),
        )
