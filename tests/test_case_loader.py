"""Unit tests for NetSage AI case loader and NetworkCase model."""

from pathlib import Path
import pytest
from pydantic import ValidationError

from netsage.models import NetworkCase
from netsage.case_loader import CaseLoader, load_cases, get_case, REQUIRED_COLUMNS


def test_load_all_30_cases_from_dataset() -> None:
    """Verify that all 30 benchmark cases are loaded successfully from the workspace dataset."""
    cases = load_cases()
    assert len(cases) == 30
    assert all(isinstance(case, NetworkCase) for case in cases)


def test_case_ids_sequence_net_001_to_030() -> None:
    """Verify that cases NET-001 through NET-030 are uniquely and sequentially present."""
    cases = load_cases()
    case_ids = [case.case_id for case in cases]

    assert len(case_ids) == 30
    assert len(set(case_ids)) == 30

    expected_ids = [f"NET-{i:03d}" for i in range(1, 31)]
    assert case_ids == expected_ids


def test_all_required_fields_populated() -> None:
    """Verify that every field of every loaded benchmark case is populated and non-empty."""
    cases = load_cases()
    for case in cases:
        assert case.case_id
        assert case.symptom
        assert case.topology_note
        assert case.show_outputs
        assert case.expected_fault
        assert case.osi_layer
        assert case.concept_tag
        assert case.severity


def test_composite_osi_layers_preserved() -> None:
    """Verify composite OSI layer labels (e.g., Layer 3/4 and Layer 2/3) are preserved."""
    net_007 = get_case("NET-007")
    assert net_007 is not None
    assert net_007.osi_layer == "Layer 3/4"

    net_028 = get_case("NET-028")
    assert net_028 is not None
    assert net_028.osi_layer == "Layer 2/3"


def test_whitespace_normalization() -> None:
    """Verify that accidental whitespace (e.g. NET-024 trailing space) is cleanly stripped."""
    net_024 = get_case("NET-024")
    assert net_024 is not None
    assert net_024.expected_fault == "VTP Domain Name Mismatch"


def test_lookup_by_case_id() -> None:
    """Verify single case retrieval by ID."""
    case = get_case("NET-001")
    assert case is not None
    assert case.case_id == "NET-001"
    assert "VLAN 30" in case.symptom
    assert case.severity == "High"
    assert case.concept_tag == "Inter-VLAN Routing"


def test_lookup_unknown_case_id() -> None:
    """Verify that retrieving a non-existent or empty case_id returns None."""
    assert get_case("NET-999") is None
    assert get_case("") is None
    assert get_case("UNKNOWN") is None


def test_missing_required_column_detection(tmp_path: Path) -> None:
    """Verify that a CSV missing any required column raises ValueError."""
    bad_csv = tmp_path / "missing_col.csv"
    bad_csv.write_text(
        "case_id,symptom,topology_note,show_outputs,expected_fault,osi_layer,concept_tag\n"
        "NET-001,Symptom,Topo,Show,Fault,Layer 3,Tag\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing required columns"):
        CaseLoader(csv_path=bad_csv)


def test_duplicate_case_id_detection(tmp_path: Path) -> None:
    """Verify that duplicate case IDs in CSV raise ValueError."""
    bad_csv = tmp_path / "dup_id.csv"
    bad_csv.write_text(
        "case_id,symptom,topology_note,show_outputs,expected_fault,osi_layer,concept_tag,severity\n"
        "NET-001,Symptom 1,Topo 1,Show 1,Fault 1,Layer 3,Tag 1,High\n"
        "NET-001,Symptom 2,Topo 2,Show 2,Fault 2,Layer 3,Tag 2,Low\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Duplicate case_id"):
        CaseLoader(csv_path=bad_csv)


def test_missing_or_empty_value_detection(tmp_path: Path) -> None:
    """Verify that empty string or missing field in CSV raises ValueError."""
    bad_csv = tmp_path / "empty_field.csv"
    bad_csv.write_text(
        "case_id,symptom,topology_note,show_outputs,expected_fault,osi_layer,concept_tag,severity\n"
        "NET-001,Symptom 1,Topo 1,Show 1,,Layer 3,Tag 1,High\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Missing required value|Empty value"):
        CaseLoader(csv_path=bad_csv)


def test_network_case_validation_and_immutability() -> None:
    """Verify NetworkCase Pydantic model validation and frozen immutability."""
    case = NetworkCase(
        case_id=" NET-100 ",
        symptom=" Host down ",
        topology_note=" R1-SW1 ",
        show_outputs=" down/down ",
        expected_fault=" Cable pulled ",
        osi_layer=" Layer 1 ",
        concept_tag=" Physical ",
        severity=" Critical ",
    )
    assert case.case_id == "NET-100"
    assert case.symptom == "Host down"
    assert case.osi_layer == "Layer 1"

    # Immutability check
    with pytest.raises(ValidationError):
        case.severity = "Low"  # type: ignore[misc]

    # Empty field check
    with pytest.raises(ValidationError):
        NetworkCase(
            case_id="",
            symptom="s",
            topology_note="t",
            show_outputs="o",
            expected_fault="f",
            osi_layer="l",
            concept_tag="c",
            severity="s",
        )
