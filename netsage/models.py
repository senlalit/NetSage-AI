"""Data models for NetSage AI."""

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

VALID_OSI_LAYERS: Set[str] = {
    "Layer 1",
    "Layer 2",
    "Layer 2/3",
    "Layer 3",
    "Layer 3/4",
    "Layer 4",
    "Layer 5",
    "Layer 6",
    "Layer 7",
}


class ReviewDecision(str, Enum):
    """Enumeration of human reviewer decisions."""

    ACCEPT = "ACCEPT"
    EDIT = "EDIT"
    REJECT = "REJECT"


class NetworkCase(BaseModel):
    """Represents a single network troubleshooting case from the benchmark dataset."""

    model_config = ConfigDict(frozen=True, str_strip_whitespace=True)

    case_id: str
    symptom: str
    topology_note: str
    show_outputs: str
    expected_fault: str
    osi_layer: str
    concept_tag: str
    severity: str

    @field_validator(
        "case_id",
        "symptom",
        "topology_note",
        "show_outputs",
        "expected_fault",
        "osi_layer",
        "concept_tag",
        "severity",
        mode="before",
    )
    @classmethod
    def validate_non_empty_string(cls, value: object) -> str:
        """Ensure string fields are valid, non-empty, and stripped of extraneous whitespace."""
        if value is None:
            raise ValueError("Field cannot be None")
        str_val = str(value).strip()
        if not str_val:
            raise ValueError("Field cannot be empty")
        return str_val


class DeterministicFinding(BaseModel):
    """A single factual anomaly or condition detected by a deterministic rule."""

    model_config = ConfigDict(frozen=True, str_strip_whitespace=True)

    rule_id: str
    status: str
    evidence: str
    message: str

    @field_validator("rule_id", "status", "evidence", "message", mode="before")
    @classmethod
    def validate_non_empty_string(cls, value: object) -> str:
        """Ensure finding fields are valid non-empty strings."""
        if value is None:
            raise ValueError("Field cannot be None")
        str_val = str(value).strip()
        if not str_val:
            raise ValueError("Field cannot be empty")
        return str_val


class DeterministicResult(BaseModel):
    """Aggregated output from executing all deterministic diagnostic rules."""

    model_config = ConfigDict(frozen=True)

    findings: List[DeterministicFinding]
    rules_checked: int

    @field_validator("rules_checked")
    @classmethod
    def validate_rules_checked(cls, value: int) -> int:
        """Ensure rules_checked count is non-negative."""
        if value < 0:
            raise ValueError("rules_checked cannot be negative")
        return value


class AIDiagnosisOutput(BaseModel):
    """Structured, evidence-grounded diagnostic output produced by the AI diagnostic engine."""

    model_config = ConfigDict(frozen=True, str_strip_whitespace=True)

    root_cause: str
    osi_layer: str
    confidence: float
    evidence: List[str]
    next_command: str
    fix_steps: List[str]

    @field_validator("root_cause", "next_command", mode="before")
    @classmethod
    def validate_non_empty_text(cls, value: object) -> str:
        """Ensure non-empty text fields."""
        if value is None:
            raise ValueError("Field cannot be None")
        str_val = str(value).strip()
        if not str_val:
            raise ValueError("Field cannot be empty")
        return str_val

    @field_validator("osi_layer", mode="before")
    @classmethod
    def validate_osi_layer(cls, value: object) -> str:
        """Ensure OSI layer is one of the supported standard or composite layer strings."""
        if value is None:
            raise ValueError("osi_layer cannot be None")
        str_val = str(value).strip()
        if str_val not in VALID_OSI_LAYERS:
            raise ValueError(f"Invalid osi_layer '{str_val}'. Must be one of: {sorted(VALID_OSI_LAYERS)}")
        return str_val

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, value: float) -> float:
        """Ensure confidence is between 0.0 and 1.0."""
        if not (0.0 <= value <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {value}")
        return float(value)

    @field_validator("evidence", "fix_steps", mode="before")
    @classmethod
    def validate_non_empty_list(cls, value: object) -> List[str]:
        """Ensure list contains at least one non-empty string item."""
        if not isinstance(value, list) or len(value) == 0:
            raise ValueError("List must contain at least one item")
        cleaned: List[str] = []
        for item in value:
            if item is None:
                raise ValueError("List item cannot be None")
            s = str(item).strip()
            if not s:
                raise ValueError("List item cannot be empty string")
            cleaned.append(s)
        if not cleaned:
            raise ValueError("List must contain at least one non-empty string")
        return cleaned


class HumanReview(BaseModel):
    """Represents a human engineer's review decision and notes on an AI diagnosis."""

    model_config = ConfigDict(frozen=True)

    decision: str
    reviewer_notes: str = ""
    reviewed_at: Optional[str] = None
    edited_diagnosis: Optional[AIDiagnosisOutput] = None
    rejection_reason: Optional[str] = None

    @field_validator("decision", mode="before")
    @classmethod
    def validate_decision(cls, value: object) -> str:
        """Validate decision matches ACCEPT, EDIT, or REJECT."""
        if value is None:
            raise ValueError("Decision cannot be None")
        dec = str(value).strip().upper()
        if dec not in {"ACCEPT", "EDIT", "REJECT"}:
            raise ValueError(f"Invalid review decision '{dec}'. Must be ACCEPT, EDIT, or REJECT.")
        return dec

    @model_validator(mode="after")
    def validate_conditional_fields(self) -> "HumanReview":
        """Validate required fields based on decision type."""
        if self.decision == "EDIT":
            if self.edited_diagnosis is None:
                raise ValueError("edited_diagnosis is required when decision is EDIT.")
        elif self.decision == "REJECT":
            if not self.rejection_reason or not self.rejection_reason.strip():
                raise ValueError("rejection_reason is required when decision is REJECT.")
        elif self.decision == "ACCEPT":
            if self.edited_diagnosis is not None:
                raise ValueError("edited_diagnosis should not be provided when decision is ACCEPT.")
        return self


class AuditRecord(BaseModel):
    """Immutable persistent audit record capturing the full diagnostic and review lifecycle."""

    model_config = ConfigDict(frozen=True)

    audit_id: str
    case_id: str
    timestamp: str
    deterministic_result: DeterministicResult
    ai_diagnosis: AIDiagnosisOutput
    review_decision: str
    final_approved_output: Optional[AIDiagnosisOutput] = None
    reviewer_notes: str = ""
    was_ai_corrected: bool
    edit_diff: Optional[Dict[str, Dict[str, Any]]] = None
    rejection_reason: Optional[str] = None

    @field_validator("audit_id", "case_id", "timestamp", "review_decision", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: object) -> str:
        """Ensure core string fields are non-empty."""
        if value is None:
            raise ValueError("Field cannot be None")
        s = str(value).strip()
        if not s:
            raise ValueError("Field cannot be empty")
        return s
