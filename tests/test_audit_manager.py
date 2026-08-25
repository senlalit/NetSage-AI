"""Unit tests for NetSage AI Human-in-the-Loop review and audit ledger system."""

from pathlib import Path
import pytest
from pydantic import ValidationError

from netsage.case_loader import get_case, load_cases
from netsage.deterministic_engine import run_deterministic_checks
from netsage.ai_engine import AIEngine, UngroundedEvidenceError
from netsage.models import (
    AIDiagnosisOutput,
    AuditRecord,
    HumanReview,
    ReviewDecision,
)
from netsage.audit_manager import (
    AuditManager,
    compute_edit_diff,
    review_diagnosis,
)


@pytest.fixture
def temp_audit_manager(tmp_path: Path) -> AuditManager:
    """Fixture providing an AuditManager backed by an isolated temporary JSON ledger."""
    ledger_file = tmp_path / "test_audit_log.json"
    return AuditManager(ledger_path=ledger_file)


def test_compute_edit_diff_detects_only_changed_fields() -> None:
    """Verify compute_edit_diff captures only modified attributes."""
    before = AIDiagnosisOutput(
        root_cause="Original Root Cause",
        osi_layer="Layer 3",
        confidence=0.90,
        evidence=["Evidence 1"],
        next_command="show ip interface brief",
        fix_steps=["step 1", "step 2"],
    )

    after = AIDiagnosisOutput(
        root_cause="Corrected Root Cause",
        osi_layer="Layer 3",
        confidence=0.98,
        evidence=["Evidence 1"],
        next_command="show ip interface brief",
        fix_steps=["step 1", "step 2", "step 3"],
    )

    diff = compute_edit_diff(before, after)
    assert "root_cause" in diff
    assert diff["root_cause"]["before"] == "Original Root Cause"
    assert diff["root_cause"]["after"] == "Corrected Root Cause"

    assert "confidence" in diff
    assert diff["confidence"]["before"] == 0.90
    assert diff["confidence"]["after"] == 0.98

    assert "fix_steps" in diff
    assert diff["fix_steps"]["before"] == ["step 1", "step 2"]
    assert diff["fix_steps"]["after"] == ["step 1", "step 2", "step 3"]

    # Unchanged fields must NOT be present in diff
    assert "osi_layer" not in diff
    assert "evidence" not in diff
    assert "next_command" not in diff


def test_human_review_model_validation() -> None:
    """Verify conditional validation rules for HumanReview model."""
    valid_diag = AIDiagnosisOutput(
        root_cause="Valid Cause",
        osi_layer="Layer 2",
        confidence=0.9,
        evidence=["Evidence"],
        next_command="show vlan",
        fix_steps=["step 1"],
    )

    # Valid ACCEPT
    review_accept = HumanReview(decision="ACCEPT", reviewer_notes="Looks solid.")
    assert review_accept.decision == "ACCEPT"

    # ACCEPT with edited_diagnosis should raise ValidationError
    with pytest.raises(ValidationError):
        HumanReview(decision="ACCEPT", edited_diagnosis=valid_diag)

    # EDIT without edited_diagnosis should raise ValidationError
    with pytest.raises(ValidationError):
        HumanReview(decision="EDIT", reviewer_notes="Fixing confidence")

    # Valid EDIT
    review_edit = HumanReview(decision="EDIT", edited_diagnosis=valid_diag, reviewer_notes="Corrected")
    assert review_edit.decision == "EDIT"
    assert review_edit.edited_diagnosis == valid_diag

    # REJECT without rejection_reason should raise ValidationError
    with pytest.raises(ValidationError):
        HumanReview(decision="REJECT")

    # Valid REJECT
    review_reject = HumanReview(decision="REJECT", rejection_reason="Inapplicable recommendation.")
    assert review_reject.decision == "REJECT"
    assert review_reject.rejection_reason == "Inapplicable recommendation."

    # Invalid decision string
    with pytest.raises(ValidationError):
        HumanReview(decision="MAYBE")


def test_accept_workflow(temp_audit_manager: AuditManager) -> None:
    """Verify ACCEPT workflow persists correctly without modifying original AI diagnosis."""
    case = get_case("NET-001")
    assert case is not None
    det_res = run_deterministic_checks(case)
    ai_engine = AIEngine()
    ai_diag = ai_engine.diagnose(case, det_res)

    review = HumanReview(decision="ACCEPT", reviewer_notes="Approved for maintenance window.")
    record = temp_audit_manager.review_diagnosis(case, det_res, ai_diag, review)

    assert record.case_id == "NET-001"
    assert record.review_decision == "ACCEPT"
    assert record.ai_diagnosis == ai_diag
    assert record.final_approved_output == ai_diag
    assert record.was_ai_corrected is False
    assert record.edit_diff is None
    assert record.reviewer_notes == "Approved for maintenance window."
    assert temp_audit_manager.count_records() == 1


def test_edit_workflow(temp_audit_manager: AuditManager) -> None:
    """Verify EDIT workflow captures diff, updates final approved output, and sets was_ai_corrected=True."""
    case = get_case("NET-006")
    assert case is not None
    det_res = run_deterministic_checks(case)
    ai_engine = AIEngine()
    ai_diag = ai_engine.diagnose(case, det_res)

    # Reviewer edits the fix steps and confidence using grounded evidence from the case
    edited_diag = AIDiagnosisOutput(
        root_cause=ai_diag.root_cause,
        osi_layer=ai_diag.osi_layer,
        confidence=0.99,
        evidence=ai_diag.evidence,
        next_command="show ip nat translations verbose",
        fix_steps=[
            "configure terminal",
            "ip nat inside source list 1 interface Gi0/1 overload",
            "end",
            "write memory",
        ],
    )

    review = HumanReview(
        decision="EDIT",
        edited_diagnosis=edited_diag,
        reviewer_notes="Added write memory and enhanced next command.",
    )
    record = temp_audit_manager.review_diagnosis(case, det_res, ai_diag, review)

    assert record.case_id == "NET-006"
    assert record.review_decision == "EDIT"
    assert record.ai_diagnosis == ai_diag  # Original remains completely intact
    assert record.final_approved_output == edited_diag
    assert record.was_ai_corrected is True
    assert record.edit_diff is not None
    assert "confidence" in record.edit_diff
    assert "next_command" in record.edit_diff
    assert "fix_steps" in record.edit_diff
    assert "root_cause" not in record.edit_diff


def test_reject_workflow(temp_audit_manager: AuditManager) -> None:
    """Verify REJECT workflow records rejection reason and leaves final_approved_output as None."""
    case = get_case("NET-003")
    assert case is not None
    det_res = run_deterministic_checks(case)
    ai_engine = AIEngine()
    ai_diag = ai_engine.diagnose(case, det_res)

    review = HumanReview(
        decision="REJECT",
        rejection_reason="DNS server was decommissioned; static hosts file required instead.",
        reviewer_notes="Escalate to DNS architecture team.",
    )
    record = temp_audit_manager.review_diagnosis(case, det_res, ai_diag, review)

    assert record.case_id == "NET-003"
    assert record.review_decision == "REJECT"
    assert record.ai_diagnosis == ai_diag
    assert record.final_approved_output is None
    assert record.was_ai_corrected is True
    assert record.rejection_reason == "DNS server was decommissioned; static hosts file required instead."


def test_ungrounded_edited_evidence_is_rejected(temp_audit_manager: AuditManager) -> None:
    """Verify that human edits containing ungrounded or fabricated evidence are blocked."""
    case = get_case("NET-001")
    assert case is not None
    det_res = run_deterministic_checks(case)
    ai_engine = AIEngine()
    ai_diag = ai_engine.diagnose(case, det_res)

    # Edit containing fabricated BGP telemetry not present in NET-001
    hallucinated_edit = AIDiagnosisOutput(
        root_cause="BGP session down",
        osi_layer="Layer 3",
        confidence=0.95,
        evidence=["BGP neighbor 10.255.255.1 Active down state hold timer expired"],
        next_command="show ip bgp summary",
        fix_steps=["router bgp 65001", "neighbor 10.255.255.1 remote-as 65002"],
    )

    review = HumanReview(decision="EDIT", edited_diagnosis=hallucinated_edit)
    with pytest.raises(UngroundedEvidenceError):
        temp_audit_manager.review_diagnosis(case, det_res, ai_diag, review)


def test_persistence_and_reloading(tmp_path: Path) -> None:
    """Verify that records written to JSON survive manager re-instantiation."""
    ledger_file = tmp_path / "persistent_ledger.json"
    mgr1 = AuditManager(ledger_path=ledger_file)

    case = get_case("NET-002")
    assert case is not None
    det_res = run_deterministic_checks(case)
    ai_diag = AIEngine().diagnose(case, det_res)

    record1 = mgr1.review_diagnosis(
        case,
        det_res,
        ai_diag,
        HumanReview(decision="ACCEPT", reviewer_notes="Initial test"),
    )

    # Second manager instance pointing to the same file
    mgr2 = AuditManager(ledger_path=ledger_file)
    assert mgr2.count_records() == 1
    loaded_record = mgr2.get_record(record1.audit_id)
    assert loaded_record is not None
    assert loaded_record.audit_id == record1.audit_id
    assert loaded_record.case_id == "NET-002"
    assert loaded_record.ai_diagnosis == ai_diag


def test_querying_and_unique_audit_ids(temp_audit_manager: AuditManager) -> None:
    """Verify retrieval by audit_id, case_id, and uniqueness of generated IDs."""
    case1 = get_case("NET-004")
    case2 = get_case("NET-005")
    assert case1 is not None and case2 is not None

    ai_engine = AIEngine()
    det1 = run_deterministic_checks(case1)
    det2 = run_deterministic_checks(case2)

    diag1 = ai_engine.diagnose(case1, det1)
    diag2 = ai_engine.diagnose(case2, det2)

    rec1 = temp_audit_manager.review_diagnosis(case1, det1, diag1, HumanReview(decision="ACCEPT"))
    rec2 = temp_audit_manager.review_diagnosis(case1, det1, diag1, HumanReview(decision="REJECT", rejection_reason="Second review"))
    rec3 = temp_audit_manager.review_diagnosis(case2, det2, diag2, HumanReview(decision="ACCEPT"))

    # IDs must be unique
    assert rec1.audit_id != rec2.audit_id
    assert rec2.audit_id != rec3.audit_id

    # Lookup by ID
    assert temp_audit_manager.get_record(rec1.audit_id) is not None
    assert temp_audit_manager.get_record("NON_EXISTENT") is None

    # Lookup by case_id
    net004_records = temp_audit_manager.get_records_by_case_id("NET-004")
    assert len(net004_records) == 2
    net005_records = temp_audit_manager.get_records_by_case_id("NET-005")
    assert len(net005_records) == 1
    assert len(temp_audit_manager.get_records_by_case_id("NET-999")) == 0


def test_audit_metrics_calculation(temp_audit_manager: AuditManager) -> None:
    """Verify deterministic audit metrics calculations."""
    cases = load_cases()
    case1, case2, case3 = cases[0], cases[1], cases[2]
    ai_engine = AIEngine()

    det1, det2, det3 = run_deterministic_checks(case1), run_deterministic_checks(case2), run_deterministic_checks(case3)
    diag1, diag2, diag3 = ai_engine.diagnose(case1, det1), ai_engine.diagnose(case2, det2), ai_engine.diagnose(case3, det3)

    # 1 ACCEPT, 1 EDIT, 1 REJECT
    temp_audit_manager.review_diagnosis(case1, det1, diag1, HumanReview(decision="ACCEPT"))

    edited_diag2 = AIDiagnosisOutput(
        root_cause="Manual edit",
        osi_layer=diag2.osi_layer,
        confidence=1.0,
        evidence=diag2.evidence,
        next_command=diag2.next_command,
        fix_steps=diag2.fix_steps,
    )
    temp_audit_manager.review_diagnosis(case2, det2, diag2, HumanReview(decision="EDIT", edited_diagnosis=edited_diag2))
    temp_audit_manager.review_diagnosis(case3, det3, diag3, HumanReview(decision="REJECT", rejection_reason="Wrong"))

    metrics = temp_audit_manager.calculate_metrics(cases=cases)
    assert metrics["total_reviewed"] == 3
    assert metrics["accepted_count"] == 1
    assert metrics["edited_count"] == 1
    assert metrics["rejected_count"] == 1
    assert metrics["acceptance_rate"] == round(1 / 3, 4)
    assert metrics["rejection_rate"] == round(1 / 3, 4)
    assert metrics["ai_correction_rate"] == round(2 / 3, 4)  # 2 corrected out of 3
    assert metrics["avg_ai_confidence"] > 0.0
    assert metrics["avg_final_confidence"] > 0.0
    assert len(metrics["count_by_osi_layer"]) >= 1


def test_empty_audit_metrics(temp_audit_manager: AuditManager) -> None:
    """Verify metrics calculation on an empty ledger returns zeroed structure."""
    metrics = temp_audit_manager.calculate_metrics()
    assert metrics["total_reviewed"] == 0
    assert metrics["accepted_count"] == 0
    assert metrics["edited_count"] == 0
    assert metrics["rejected_count"] == 0
    assert metrics["ai_correction_rate"] == 0.0
