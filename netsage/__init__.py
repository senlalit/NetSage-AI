"""NetSage AI: Cisco & Packet Tracer Network Troubleshooting Assistant."""

import os

__version__ = "1.0.0"
NETSAGE_VERSION = "1.0.0"


def load_dotenv(env_path: str = ".env") -> None:
    """Load key-value pairs from a .env file into os.environ if not already set."""
    if os.path.isfile(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip()
                        if k and v and k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass


load_dotenv()

from netsage.models import (
    NetworkCase,
    DeterministicFinding,
    DeterministicResult,
    AIDiagnosisOutput,
    ReviewDecision,
    HumanReview,
    AuditRecord,
    VALID_OSI_LAYERS,
)
from netsage.case_loader import CaseLoader, load_cases, get_case
from netsage.deterministic_engine import (
    DeterministicEngine,
    run_deterministic_checks,
    ALL_RULES,
)
from netsage.ai_engine import (
    AIProvider,
    OfflineDeterministicProvider,
    GeminiProvider,
    AIEngine,
    diagnose,
    UngroundedEvidenceError,
    validate_grounding,
)
from netsage.prompt_templates import SYSTEM_PROMPT, build_user_prompt
from netsage.audit_manager import (
    AuditManager,
    compute_edit_diff,
    review_diagnosis,
    DEFAULT_AUDIT_LOG_PATH,
)
from netsage.system_health import get_system_status
from netsage.logging_config import get_logger, setup_logging

__all__ = [
    "__version__",
    "NETSAGE_VERSION",
    "NetworkCase",
    "DeterministicFinding",
    "DeterministicResult",
    "AIDiagnosisOutput",
    "ReviewDecision",
    "HumanReview",
    "AuditRecord",
    "VALID_OSI_LAYERS",
    "CaseLoader",
    "load_cases",
    "get_case",
    "DeterministicEngine",
    "run_deterministic_checks",
    "ALL_RULES",
    "AIProvider",
    "OfflineDeterministicProvider",
    "GeminiProvider",
    "AIEngine",
    "diagnose",
    "UngroundedEvidenceError",
    "validate_grounding",
    "SYSTEM_PROMPT",
    "build_user_prompt",
    "AuditManager",
    "compute_edit_diff",
    "review_diagnosis",
    "DEFAULT_AUDIT_LOG_PATH",
    "get_system_status",
    "get_logger",
    "setup_logging",
]
