"""Unit tests for NetSage AI Evidence-Grounded AI Diagnostic Engine."""

import pytest
from pydantic import ValidationError

from netsage.case_loader import load_cases, get_case
from netsage.deterministic_engine import DeterministicEngine, run_deterministic_checks
from netsage.models import AIDiagnosisOutput, NetworkCase
from netsage.prompt_templates import SYSTEM_PROMPT, build_user_prompt
from netsage.ai_engine import (
    AIEngine,
    OfflineDeterministicProvider,
    UngroundedEvidenceError,
    diagnose,
    validate_grounding,
)


def test_valid_ai_diagnosis_output_schema() -> None:
    """Verify that a well-formed diagnosis strictly validates against AIDiagnosisOutput."""
    output = AIDiagnosisOutput(
        root_cause="Interface GigabitEthernet0/0.10 is administratively shutdown",
        osi_layer="Layer 3",
        confidence=0.95,
        evidence=["GigabitEthernet0/0.10 is administratively down"],
        next_command="show ip interface brief",
        fix_steps=["configure terminal", "interface Gi0/0.10", "no shutdown", "end"],
    )
    assert output.root_cause == "Interface GigabitEthernet0/0.10 is administratively shutdown"
    assert output.confidence == 0.95
    assert len(output.evidence) == 1
    assert len(output.fix_steps) == 4


def test_confidence_bounds_validation() -> None:
    """Verify that confidence scores outside [0.0, 1.0] are strictly rejected."""
    # Negative confidence
    with pytest.raises(ValidationError):
        AIDiagnosisOutput(
            root_cause="Test",
            osi_layer="Layer 3",
            confidence=-0.1,
            evidence=["valid evidence"],
            next_command="show version",
            fix_steps=["step 1"],
        )

    # Confidence > 1.0
    with pytest.raises(ValidationError):
        AIDiagnosisOutput(
            root_cause="Test",
            osi_layer="Layer 3",
            confidence=1.05,
            evidence=["valid evidence"],
            next_command="show version",
            fix_steps=["step 1"],
        )


def test_empty_evidence_or_fix_steps_rejected() -> None:
    """Verify that empty lists or empty string elements in evidence/fix_steps are rejected."""
    # Empty evidence list
    with pytest.raises(ValidationError):
        AIDiagnosisOutput(
            root_cause="Test",
            osi_layer="Layer 3",
            confidence=0.9,
            evidence=[],
            next_command="show version",
            fix_steps=["step 1"],
        )

    # Empty fix steps list
    with pytest.raises(ValidationError):
        AIDiagnosisOutput(
            root_cause="Test",
            osi_layer="Layer 3",
            confidence=0.9,
            evidence=["valid evidence"],
            next_command="show version",
            fix_steps=[],
        )

    # Blank whitespace item
    with pytest.raises(ValidationError):
        AIDiagnosisOutput(
            root_cause="Test",
            osi_layer="Layer 3",
            confidence=0.9,
            evidence=["   "],
            next_command="show version",
            fix_steps=["step 1"],
        )


def test_composite_and_standard_osi_layers() -> None:
    """Verify support for all standard and composite OSI layers."""
    layers = [
        "Layer 1",
        "Layer 2",
        "Layer 2/3",
        "Layer 3",
        "Layer 3/4",
        "Layer 4",
        "Layer 5",
        "Layer 6",
        "Layer 7",
    ]
    for layer in layers:
        out = AIDiagnosisOutput(
            root_cause="Fault",
            osi_layer=layer,
            confidence=0.9,
            evidence=["evidence snippet"],
            next_command="show ip route",
            fix_steps=["step"],
        )
        assert out.osi_layer == layer

    # Invalid OSI layer string
    with pytest.raises(ValidationError):
        AIDiagnosisOutput(
            root_cause="Fault",
            osi_layer="Layer 8",
            confidence=0.9,
            evidence=["evidence snippet"],
            next_command="show ip route",
            fix_steps=["step"],
        )


def test_grounded_evidence_passes_validation() -> None:
    """Verify that evidence strictly present in case telemetry passes grounding check."""
    case = get_case("NET-001")
    assert case is not None
    det_res = run_deterministic_checks(case)

    diagnosis = AIDiagnosisOutput(
        root_cause="Sub-interface administratively down",
        osi_layer="Layer 3",
        confidence=0.96,
        evidence=["GigabitEthernet0/0.10 is administratively down line protocol is down"],
        next_command="show ip interface brief",
        fix_steps=["configure terminal", "interface Gi0/0.10", "no shutdown", "end"],
    )

    # Should not raise any error
    validate_grounding(case, diagnosis, det_res)


def test_ungrounded_evidence_raises_error() -> None:
    """Verify that hallucinated evidence not in case telemetry is rejected."""
    case = get_case("NET-001")
    assert case is not None
    det_res = run_deterministic_checks(case)

    hallucinated_diagnosis = AIDiagnosisOutput(
        root_cause="BGP session flapping",
        osi_layer="Layer 3",
        confidence=0.99,
        evidence=["BGP neighbor 192.0.2.1 state Active down with hold timer expired error code 3"],
        next_command="show ip bgp summary",
        fix_steps=["router bgp 65000", "neighbor 192.0.2.1 remote-as 65001"],
    )

    with pytest.raises(UngroundedEvidenceError, match="Ungrounded evidence detected"):
        validate_grounding(case, hallucinated_diagnosis, det_res)


def test_expected_fault_isolation_in_prompt_and_reasoning() -> None:
    """Verify that prompt builder and diagnostic reasoning receive zero input from expected_fault."""
    case = get_case("NET-004")
    assert case is not None

    # Verify build_user_prompt does not contain expected_fault
    user_prompt = build_user_prompt(case)
    assert case.expected_fault not in user_prompt
    assert "expected_fault" not in user_prompt.lower()

    # Verify with deterministic findings as well
    det_res = run_deterministic_checks(case)
    user_prompt_with_det = build_user_prompt(case, det_res)
    assert case.expected_fault not in user_prompt_with_det


def test_offline_provider_execution_all_30_cases() -> None:
    """Verify that the offline provider diagnoses all 30 benchmark cases without external API."""
    cases = load_cases()
    assert len(cases) == 30

    engine = AIEngine(provider=OfflineDeterministicProvider())

    for case in cases:
        det_res = run_deterministic_checks(case)
        diagnosis = engine.diagnose(case, det_res)

        assert isinstance(diagnosis, AIDiagnosisOutput)
        assert diagnosis.root_cause
        assert diagnosis.osi_layer in [
            "Layer 1",
            "Layer 2",
            "Layer 2/3",
            "Layer 3",
            "Layer 3/4",
            "Layer 4",
            "Layer 5",
            "Layer 6",
            "Layer 7",
        ]
        assert 0.0 <= diagnosis.confidence <= 1.0
        assert len(diagnosis.evidence) >= 1
        assert diagnosis.next_command
        assert len(diagnosis.fix_steps) >= 1


def test_offline_provider_determinism() -> None:
    """Verify that running the offline provider repeatedly yields identical diagnoses."""
    case = get_case("NET-006")
    assert case is not None

    diag1 = diagnose(case)
    diag2 = diagnose(case)

    assert diag1.root_cause == diag2.root_cause
    assert diag1.osi_layer == diag2.osi_layer
    assert diag1.confidence == diag2.confidence
    assert diag1.evidence == diag2.evidence
    assert diag1.next_command == diag2.next_command
    assert diag1.fix_steps == diag2.fix_steps


def test_end_to_end_diagnostic_pipeline() -> None:
    """Verify end-to-end flow: NetworkCase -> DeterministicEngine -> AIEngine -> AIDiagnosisOutput."""
    case = get_case("NET-014")
    assert case is not None

    det_engine = DeterministicEngine()
    det_res = det_engine.analyze_case(case)
    assert len(det_res.findings) >= 1

    ai_engine = AIEngine()
    diagnosis = ai_engine.diagnose(case, det_res)

    assert diagnosis.osi_layer == "Layer 7"
    assert "helper" in diagnosis.root_cause.lower()
    assert any("helper" in step.lower() for step in diagnosis.fix_steps)
