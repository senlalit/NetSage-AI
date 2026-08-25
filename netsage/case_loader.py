"""Case loader service for NetSage AI."""

from pathlib import Path
from typing import Dict, List, Optional, Union
import pandas as pd

from netsage.models import NetworkCase

REQUIRED_COLUMNS: List[str] = [
    "case_id",
    "symptom",
    "topology_note",
    "show_outputs",
    "expected_fault",
    "osi_layer",
    "concept_tag",
    "severity",
]

DEFAULT_CASES_PATH: Path = Path(__file__).resolve().parent.parent / "cases.csv"


class CaseLoader:
    """Service to load, validate, and retrieve benchmark network troubleshooting cases."""

    def __init__(self, csv_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize the case loader with a specific path or the default cases.csv path."""
        self.csv_path: Path = Path(csv_path) if csv_path is not None else DEFAULT_CASES_PATH
        self._cases: List[NetworkCase] = []
        self._cases_by_id: Dict[str, NetworkCase] = {}
        self.load_cases()

    def load_cases(self) -> List[NetworkCase]:
        """Load and validate all cases from the CSV file.

        Returns:
            List[NetworkCase]: Loaded and validated list of NetworkCase instances.

        Raises:
            FileNotFoundError: If the CSV file does not exist.
            ValueError: If required columns are missing, duplicate IDs exist, or fields are empty.
        """
        if not self.csv_path.exists():
            raise FileNotFoundError(f"Cases CSV file not found at: {self.csv_path}")

        df = pd.read_csv(self.csv_path, dtype=str)

        # 1. Validate required columns
        missing_columns = [col for col in REQUIRED_COLUMNS if col not in df.columns]
        if missing_columns:
            raise ValueError(f"CSV is missing required columns: {missing_columns}")

        # 2. Normalize and check for missing values
        cases: List[NetworkCase] = []
        seen_ids: set[str] = set()

        for idx, row in df.iterrows():
            row_dict: Dict[str, str] = {}
            for col in REQUIRED_COLUMNS:
                raw_val = row[col]
                if pd.isna(raw_val):
                    raise ValueError(f"Missing required value for column '{col}' at row {idx + 1}")
                str_val = str(raw_val).strip()
                if not str_val:
                    raise ValueError(f"Empty value for column '{col}' at row {idx + 1}")
                row_dict[col] = str_val

            case_id = row_dict["case_id"]
            if case_id in seen_ids:
                raise ValueError(f"Duplicate case_id detected: '{case_id}' at row {idx + 1}")
            seen_ids.add(case_id)

            case = NetworkCase(**row_dict)
            cases.append(case)

        self._cases = cases
        self._cases_by_id = {case.case_id: case for case in cases}
        return self._cases

    def get_all_cases(self) -> List[NetworkCase]:
        """Return all loaded cases."""
        return list(self._cases)

    def get_case(self, case_id: str) -> Optional[NetworkCase]:
        """Retrieve a single case by its case_id.

        Args:
            case_id: The ID of the case to retrieve (e.g., 'NET-001').

        Returns:
            Optional[NetworkCase]: The matching NetworkCase, or None if not found.
        """
        if not case_id:
            return None
        return self._cases_by_id.get(case_id.strip())


def load_cases(csv_path: Optional[Union[str, Path]] = None) -> List[NetworkCase]:
    """Load all cases using CaseLoader."""
    loader = CaseLoader(csv_path=csv_path)
    return loader.get_all_cases()


def get_case(case_id: str, csv_path: Optional[Union[str, Path]] = None) -> Optional[NetworkCase]:
    """Retrieve a single case by ID using CaseLoader."""
    loader = CaseLoader(csv_path=csv_path)
    return loader.get_case(case_id)
