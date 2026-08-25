"""Audit Ledger and Human-in-the-Loop review management for NetSage AI.

Provides persistent JSON-backed audit logging, atomic writes, edit-diff tracking,
review decision handling, and compliance analytics for responsible AI network troubleshooting.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from netsage.ai_engine import validate_grounding
from netsage.logging_config import get_logger
from netsage.models import (
    AIDiagnosisOutput,
    AuditRecord,
    DeterministicResult,
    HumanReview,
    NetworkCase,
)

logger = get_logger("audit_manager")

DEFAULT_AUDIT_LOG_PATH: Path = Path(__file__).resolve().parent.parent / "audit_log.json"


def compute_edit_diff(before: AIDiagnosisOutput, after: AIDiagnosisOutput) -> Dict[str, Dict[str, Any]]:
    """Compute structured field-level difference between original AI output and human edit.

    Args:
        before: Original AI diagnosis.
        after: Human-edited diagnosis.

    Returns:
        Dict[str, Dict[str, Any]]: Dictionary containing only changed fields with before/after values.
    """
    diff: Dict[str, Dict[str, Any]] = {}
    fields_to_compare = [
        "root_cause",
        "osi_layer",
        "confidence",
        "evidence",
        "next_command",
        "fix_steps",
    ]

    for field in fields_to_compare:
        b_val = getattr(before, field)
        a_val = getattr(after, field)
        if b_val != a_val:
            diff[field] = {
                "before": b_val,
                "after": a_val,
            }

    return diff


class AuditManager:
    """Manages persistent audit records, review lifecycle, and compliance metrics with atomic persistence."""

    def __init__(self, ledger_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize the audit manager with a custom or default ledger file path."""
        self.ledger_path: Path = Path(ledger_path) if ledger_path is not None else DEFAULT_AUDIT_LOG_PATH

    @property
    def log_path(self) -> str:
        """Return the string representation of the ledger path."""
        return str(self.ledger_path)

    def _read_records_raw(self) -> List[Dict[str, Any]]:
        """Read raw dictionary records from JSON file with corruption tolerance."""
        if not self.ledger_path.exists():
            return []
        try:
            content = self.ledger_path.read_text(encoding="utf-8").strip()
            if not content:
                return []
            data = json.loads(content)
            if isinstance(data, list):
                return data
            logger.warning("Audit ledger root is not a list; returning empty records.")
            return []
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Error reading audit ledger at {self.ledger_path}: {e}. Returning empty records.")
            return []

    def _write_records_raw(self, raw_records: List[Dict[str, Any]]) -> None:
        """Atomically write raw dictionary records to JSON file."""
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        target_dir = self.ledger_path.parent
        target_name = self.ledger_path.name

        # Atomic write via temporary file in same directory
        temp_file = target_dir / f"{target_name}.tmp"
        try:
            serialized = json.dumps(raw_records, indent=2)
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(serialized)
                f.flush()
                os.fsync(f.fileno())
            # Atomic rename / replace
            os.replace(temp_file, self.ledger_path)
        except Exception as e:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass
            logger.error(f"Failed atomic write to audit ledger: {e}")
            raise

    def append_record(self, record: AuditRecord) -> None:
        """Append an immutable audit record to the persistent ledger.

        Args:
            record: The AuditRecord instance to append.
        """
        raw_records = self._read_records_raw()
        raw_records.append(record.model_dump())
        self._write_records_raw(raw_records)
        logger.info(f"Audit record {record.audit_id} successfully persisted for Case {record.case_id} [{record.review_decision}]")

    def get_all_records(self) -> List[AuditRecord]:
        """Retrieve all valid audit records from the ledger."""
        raw_records = self._read_records_raw()
        valid_records: List[AuditRecord] = []
        for idx, item in enumerate(raw_records):
            try:
                valid_records.append(AuditRecord(**item))
            except Exception as e:
                logger.warning(f"Skipping malformed audit record at index {idx}: {e}")
        return valid_records

    def count_records(self) -> int:
        """Return the total number of records in the audit ledger."""
        return len(self.get_all_records())

    def get_record(self, audit_id: str) -> Optional[AuditRecord]:
        """Look up a specific audit record by its unique audit_id."""
        for record in self.get_all_records():
            if record.audit_id == audit_id:
                return record
        return None

    def get_records_by_case_id(self, case_id: str) -> List[AuditRecord]:
        """Look up all audit records for a given case_id."""
        return [r for r in self.get_all_records() if r.case_id == case_id]

    def get_records_by_case(self, case_id: str) -> List[AuditRecord]:
        """Alias for get_records_by_case_id."""
        return self.get_records_by_case_id(case_id)

    def review_diagnosis(
        self,
        case: NetworkCase,
        deterministic_result: DeterministicResult,
        ai_diagnosis: AIDiagnosisOutput,
        review: HumanReview,
    ) -> AuditRecord:
        """Execute a human review decision and record the resulting audit entry.

        Args:
            case: The source NetworkCase.
            deterministic_result: The deterministic engine findings.
            ai_diagnosis: The initial proposal from the AI engine.
            review: The HumanReview specifying the decision and modifications.

        Returns:
            AuditRecord: The saved immutable audit record.
        """
        audit_id = f"AUD-{uuid4().hex[:12].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        final_output: Optional[AIDiagnosisOutput] = None
        edit_diff: Optional[Dict[str, Dict[str, Any]]] = None
        was_corrected: bool = False

        if review.decision == "ACCEPT":
            final_output = ai_diagnosis
            was_corrected = False
            edit_diff = None

        elif review.decision == "EDIT":
            if review.edited_diagnosis is None:
                raise ValueError("An edited diagnosis must be provided when decision is EDIT.")

            # Validate evidence grounding on human edit
            validate_grounding(case, review.edited_diagnosis, deterministic_result)

            final_output = review.edited_diagnosis
            edit_diff = compute_edit_diff(ai_diagnosis, review.edited_diagnosis)
            was_corrected = True

        elif review.decision == "REJECT":
            if not review.rejection_reason or not review.rejection_reason.strip():
                raise ValueError("A rejection reason is mandatory when decision is REJECT.")
            final_output = None
            edit_diff = None
            was_corrected = True

        record = AuditRecord(
            audit_id=audit_id,
            case_id=case.case_id,
            timestamp=timestamp,
            deterministic_result=deterministic_result,
            review_decision=review.decision,
            ai_diagnosis=ai_diagnosis,
            final_approved_output=final_output,
            was_ai_corrected=was_corrected,
            edit_diff=edit_diff,
            reviewer_notes=review.reviewer_notes or "",
            rejection_reason=review.rejection_reason,
        )

        self.append_record(record)
        return record

    def calculate_metrics(self, cases: Optional[List[NetworkCase]] = None) -> Dict[str, Any]:
        """Calculate aggregate review metrics, acceptance rates, and confidence distributions."""
        records = self.get_all_records()
        total = len(records)

        if total == 0:
            return {
                "total_reviewed": 0,
                "accepted_count": 0,
                "edited_count": 0,
                "rejected_count": 0,
                "acceptance_rate": 0.0,
                "ai_correction_rate": 0.0,
                "rejection_rate": 0.0,
                "avg_ai_confidence": 0.0,
                "avg_final_confidence": 0.0,
                "count_by_osi_layer": {},
                "count_by_severity": {},
            }

        accepted = [r for r in records if r.review_decision == "ACCEPT"]
        edited = [r for r in records if r.review_decision == "EDIT"]
        rejected = [r for r in records if r.review_decision == "REJECT"]

        ai_confs = [r.ai_diagnosis.confidence for r in records]
        final_confs = [r.final_approved_output.confidence for r in records if r.final_approved_output is not None]

        osi_dist: Dict[str, int] = {}
        for r in records:
            layer = r.final_approved_output.osi_layer if r.final_approved_output else r.ai_diagnosis.osi_layer
            osi_dist[layer] = osi_dist.get(layer, 0) + 1

        case_lookup: Dict[str, NetworkCase] = {c.case_id: c for c in cases} if cases else {}
        sev_dist: Dict[str, int] = {}
        for r in records:
            if r.case_id in case_lookup:
                sev = case_lookup[r.case_id].severity
                sev_dist[sev] = sev_dist.get(sev, 0) + 1

        corrected = [r for r in records if r.was_ai_corrected]

        return {
            "total_reviewed": total,
            "accepted_count": len(accepted),
            "edited_count": len(edited),
            "rejected_count": len(rejected),
            "acceptance_rate": round(len(accepted) / total, 4),
            "ai_correction_rate": round(len(corrected) / total, 4),
            "rejection_rate": round(len(rejected) / total, 4),
            "avg_ai_confidence": round(sum(ai_confs) / len(ai_confs), 4) if ai_confs else 0.0,
            "avg_final_confidence": round(sum(final_confs) / len(final_confs), 4) if final_confs else 0.0,
            "count_by_osi_layer": osi_dist,
            "count_by_severity": sev_dist,
        }


def review_diagnosis(
    case: NetworkCase,
    deterministic_result: DeterministicResult,
    ai_diagnosis: AIDiagnosisOutput,
    review: HumanReview,
    ledger_path: Optional[Union[str, Path]] = None,
) -> AuditRecord:
    """Convenience helper to record a review decision to the default or specified ledger."""
    manager = AuditManager(ledger_path=ledger_path)
    return manager.review_diagnosis(case, deterministic_result, ai_diagnosis, review)
