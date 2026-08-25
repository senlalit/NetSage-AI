"""Configuration and system health tests for NetSage AI."""

import os
from pathlib import Path
import pytest

from netsage import load_dotenv
from netsage.ai_engine import AIEngine, GeminiProvider, OfflineDeterministicProvider
from netsage.system_health import get_system_status


def test_system_status_structure_and_health() -> None:
    """Verify that get_system_status reports comprehensive, non-sensitive health metadata."""
    status = get_system_status()

    assert "data_layer" in status
    assert status["data_layer"]["status"] == "OK"
    assert status["data_layer"]["cases_loaded"] == 30

    assert "deterministic_engine" in status
    assert status["deterministic_engine"]["status"] == "OK"
    assert status["deterministic_engine"]["rules_registered"] >= 28

    assert "ai_engine" in status
    assert "active_mode" in status["ai_engine"]

    assert "audit_ledger" in status
    assert status["audit_ledger"]["status"] == "OK"

    assert "safety_guarantees" in status
    assert status["safety_guarantees"]["device_execution_disabled"] is True
    assert status["safety_guarantees"]["grounding_validation_enforced"] is True


def test_system_status_never_exposes_api_key(monkeypatch) -> None:
    """Verify that get_system_status never returns the raw API key."""
    monkeypatch.setenv("GEMINI_API_KEY", "AQ.SUPER_SECRET_KEY_12345")
    status = get_system_status()

    status_str = str(status)
    assert "AQ.SUPER_SECRET_KEY_12345" not in status_str
    assert status["ai_engine"]["gemini_configured"] is True


def test_offline_mode_when_gemini_key_absent(monkeypatch) -> None:
    """Verify that absence of GEMINI_API_KEY gracefully defaults to offline mode."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    status = get_system_status()
    assert status["ai_engine"]["gemini_configured"] is False

    engine = AIEngine()
    assert isinstance(engine.provider, OfflineDeterministicProvider)


def test_gemini_provider_fails_safely_when_key_missing(monkeypatch) -> None:
    """Verify that GeminiProvider raises a clean ValueError when no key is present."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY environment variable is not set"):
        GeminiProvider(api_key=None)


def test_load_dotenv_handles_missing_file(tmp_path) -> None:
    """Verify load_dotenv gracefully handles non-existent file without exception."""
    non_existent = tmp_path / "non_existent.env"
    load_dotenv(str(non_existent))  # Should not raise
