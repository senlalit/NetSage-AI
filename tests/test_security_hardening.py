"""Security hardening test suite for NetSage AI.

Verifies:
1. Zero hardcoded secrets/API keys in codebase
2. .env.example contains safe placeholders only
3. No forbidden execution libraries (subprocess, netmiko, paramiko, os.system, etc.)
4. Secret masking in structured logging
5. expected_fault isolation from prompt construction
6. Evidence grounding bypass prevention
"""

import os
import re
from pathlib import Path
import pytest

from netsage.ai_engine import AIEngine, UngroundedEvidenceError, validate_grounding
from netsage.logging_config import SecretMaskingFilter, setup_logging
from netsage.models import AIDiagnosisOutput, NetworkCase
from netsage.prompt_templates import build_user_prompt

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_no_hardcoded_api_keys_in_source_code() -> None:
    """Verify that no actual Gemini or Google API keys are hardcoded in source files."""
    pattern = re.compile(r"AIzaSy[A-Za-z0-9_-]{33}")
    py_files = list(REPO_ROOT.glob("netsage/**/*.py")) + list(REPO_ROOT.glob("app.py"))

    for py_file in py_files:
        content = py_file.read_text(encoding="utf-8")
        matches = pattern.findall(content)
        assert len(matches) == 0, f"Found hardcoded API key in {py_file.name}: {matches}"


def test_env_example_contains_placeholders_only() -> None:
    """Verify that .env.example contains only non-sensitive placeholder tokens."""
    env_example = REPO_ROOT / ".env.example"
    assert env_example.exists(), ".env.example must exist"

    content = env_example.read_text(encoding="utf-8")
    assert "your_gemini_api_key_here" in content
    assert not re.search(r"AIzaSy[A-Za-z0-9_-]{33}", content)
    assert not re.search(r"AQ\.[A-Za-z0-9_-]+", content)


def test_no_forbidden_network_execution_modules() -> None:
    """Verify that dangerous device execution modules are completely absent from netsage/."""
    forbidden = [
        "subprocess",
        "os.system",
        "paramiko",
        "netmiko",
        "napalm",
        "fabric",
        "telnetlib",
    ]
    py_files = list((REPO_ROOT / "netsage").glob("*.py"))

    for py_file in py_files:
        content = py_file.read_text(encoding="utf-8")
        for word in forbidden:
            # Check import statements
            assert not re.search(rf"\bimport\s+{word}\b", content), f"Forbidden import '{word}' in {py_file.name}"
            assert not re.search(rf"\bfrom\s+{word}\b", content), f"Forbidden from-import '{word}' in {py_file.name}"


def test_secret_masking_in_logging() -> None:
    """Verify that SecretMaskingFilter redacts accidental API keys in log records."""
    import logging
    filter_ = SecretMaskingFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Connecting with key AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6",
        args=(),
        exc_info=None,
    )
    filter_.filter(record)
    assert "[REDACTED_SECRET]" in record.msg
    assert "AIzaSy" not in record.msg


def test_expected_fault_isolation_in_prompts() -> None:
    """Verify that benchmark expected_fault is never included in prompt templates."""
    case = NetworkCase(
        case_id="NET-999",
        symptom="Hosts cannot communicate",
        topology_note="Switch SW1 to Host1",
        show_outputs="GigabitEthernet0/1 is down",
        expected_fault="SECRET_BENCHMARK_GROUND_TRUTH_FAULT",
        osi_layer="Layer 2",
        concept_tag="Test",
        severity="High",
    )
    prompt = build_user_prompt(case)
    assert "SECRET_BENCHMARK_GROUND_TRUTH_FAULT" not in prompt
    assert "expected_fault" not in prompt


def test_grounding_validation_cannot_be_bypassed() -> None:
    """Verify that ungrounded or fabricated evidence triggers UngroundedEvidenceError."""
    case = NetworkCase(
        case_id="NET-001",
        symptom="PC1 cannot reach Server1 in VLAN 30",
        topology_note="Gateway on Router Sub-interface Gi0/0.10",
        show_outputs="GigabitEthernet0/0.10 is administratively down line protocol is down",
        expected_fault="Sub-interface administratively down",
        osi_layer="Layer 3",
        concept_tag="Inter-VLAN Routing",
        severity="High",
    )
    unverified_diag = AIDiagnosisOutput(
        root_cause="Fabricated hardware PSU failure",
        osi_layer="Layer 1",
        confidence=0.9,
        evidence=["Power Supply unit PSU-2 failed completely on core switch"],
        next_command="show environment power",
        fix_steps=["replace power supply PSU-2"],
    )

    with pytest.raises(UngroundedEvidenceError):
        validate_grounding(case, unverified_diag)
