"""End-to-end integration and runtime UI testing using Streamlit's official AppTest framework."""

from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest
from netsage.case_loader import load_cases
from netsage.audit_manager import AuditManager

APP_PATH = str(Path(__file__).parent.parent / "app.py")


def test_streamlit_app_startup_and_shell() -> None:
    """Verify that app.py loads cleanly with all tabs, titles, and no exceptions."""
    at = AppTest.from_file(APP_PATH, default_timeout=15)
    at.run()

    assert not at.exception
    assert len(at.tabs) >= 4


def test_streamlit_case_explorer_flow() -> None:
    """Verify Case Explorer rendering, filtering, and case inspection."""
    at = AppTest.from_file(APP_PATH, default_timeout=15)
    at.run()
    assert not at.exception

    # Verify selectbox for inspecting cases exists
    assert len(at.selectbox) >= 1
    # Check that dataframe with 30 cases renders
    assert len(at.dataframe) >= 1
    df = at.dataframe[0].value
    assert len(df) == 30
    assert "Case ID" in df.columns


def test_streamlit_diagnostic_and_hitl_accept_flow() -> None:
    """Verify execution of diagnosis and ACCEPT review workflow in Streamlit."""
    at = AppTest.from_file(APP_PATH, default_timeout=15)
    at.run()
    assert not at.exception

    # Select NET-001
    at.session_state.selected_case_id = "NET-001"
    at.run()
    assert not at.exception

    # Click Run Diagnosis button
    run_btn = next((b for b in at.button if "Execute Telemetry Checks" in b.label or "Diagnosis" in b.label), None)
    assert run_btn is not None
    run_btn.click().run()
    assert not at.exception

    # Verify deterministic result and AI diagnosis populated in session state
    assert at.session_state.current_det_result is not None
    assert at.session_state.current_ai_diagnosis is not None
    assert at.session_state.current_ai_diagnosis.root_cause != ""

    # Click Confirm Acceptance button
    accept_btn = next((b for b in at.button if "Confirm Acceptance" in b.label), None)
    assert accept_btn is not None
    accept_btn.click().run()
    assert not at.exception


def test_streamlit_custom_sandbox_flow() -> None:
    """Verify custom sandbox form submission, graceful validation, and analysis execution."""
    at = AppTest.from_file(APP_PATH, default_timeout=15)
    at.run()
    assert not at.exception

    # Find sandbox form submission button
    sandbox_btn = next((b for b in at.button if "Analyze Custom Telemetry" in b.label or "Analyze" in b.label), None)
    assert sandbox_btn is not None

    # Run with empty fields -> should trigger error notification gracefully without exception
    sandbox_btn.click().run()
    assert not at.exception
    assert any("required" in str(err.value).lower() for err in at.error)
