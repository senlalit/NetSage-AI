#!/usr/bin/env python3
"""Release and productization verification check script for NetSage AI.

Performs deterministic, non-network local checks to validate:
- Dataset integrity (30 benchmark cases NET-001..NET-030)
- Essential project files (.env.example, .gitignore, .streamlit/config.toml)
- Clean module imports
- Zero forbidden execution modules or hardcoded credentials
"""

import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def log_check(name: str, passed: bool, detail: str = "") -> bool:
    status_str = "[PASS]" if passed else "[FAIL]"
    print(f"{status_str} {name}" + (f": {detail}" if detail else ""))
    return passed


def check_dataset_integrity() -> bool:
    cases_file = REPO_ROOT / "cases.csv"
    if not cases_file.is_file():
        return log_check("cases.csv existence", False, "File missing")

    lines = cases_file.read_text(encoding="utf-8").strip().splitlines()
    if len(lines) != 31:
        return log_check("cases.csv line count", False, f"Expected 31 lines, got {len(lines)}")

    expected_ids = [f"NET-{i:03d}" for i in range(1, 31)]
    actual_ids = [line.split(",")[0].strip() for line in lines[1:]]

    if actual_ids != expected_ids:
        return log_check("cases.csv case IDs", False, f"Expected NET-001..NET-030, got mismatch")

    return log_check("cases.csv dataset integrity", True, "30 benchmark cases NET-001 through NET-030 verified")


def check_required_files() -> bool:
    required = [
        "app.py",
        "requirements.txt",
        "README.md",
        ".gitignore",
        ".env.example",
        ".streamlit/config.toml",
        "netsage/__init__.py",
        "netsage/models.py",
        "netsage/case_loader.py",
        "netsage/deterministic_engine.py",
        "netsage/prompt_templates.py",
        "netsage/ai_engine.py",
        "netsage/audit_manager.py",
        "netsage/ui_components.py",
        "netsage/logging_config.py",
        "netsage/system_health.py",
    ]
    all_ok = True
    for rel_path in required:
        target = REPO_ROOT / rel_path
        if not target.is_file():
            log_check(f"Required file: {rel_path}", False, "File missing")
            all_ok = False
    if all_ok:
        log_check("Required repository files", True, f"All {len(required)} core files present")
    return all_ok


def check_env_example_safety() -> bool:
    env_ex = REPO_ROOT / ".env.example"
    if not env_ex.is_file():
        return log_check(".env.example safety", False, ".env.example missing")

    content = env_ex.read_text(encoding="utf-8")
    if "AIzaSy" in content or "AQ." in content:
        return log_check(".env.example safety", False, "Found potential real credential in template")

    if "your_gemini_api_key_here" not in content:
        return log_check(".env.example safety", False, "Placeholder token missing")

    return log_check(".env.example safety", True, "Template contains safe placeholders only")


def check_no_forbidden_execution_imports() -> bool:
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
    violations = []

    for f in py_files:
        content = f.read_text(encoding="utf-8")
        for word in forbidden:
            if re.search(rf"\bimport\s+{word}\b", content) or re.search(rf"\bfrom\s+{word}\b", content):
                violations.append(f"{f.name}: {word}")

    if violations:
        return log_check("No device execution imports", False, f"Violations found: {violations}")

    return log_check("No device execution imports", True, "Verified clean - zero execution libraries")


def check_no_hardcoded_keys() -> bool:
    pattern = re.compile(r"AIzaSy[A-Za-z0-9_-]{33}")
    py_files = list((REPO_ROOT / "netsage").glob("*.py")) + [REPO_ROOT / "app.py"]
    violations = []

    for f in py_files:
        content = f.read_text(encoding="utf-8")
        if pattern.search(content):
            violations.append(f.name)

    if violations:
        return log_check("No hardcoded keys in source", False, f"Violations in: {violations}")

    return log_check("No hardcoded keys in source", True, "Verified clean - zero keys in source code")


def check_imports_and_health() -> bool:
    try:
        from netsage import __version__, get_system_status, load_cases
        cases = load_cases()
        status = get_system_status()
        if len(cases) != 30 or status["data_layer"]["status"] != "OK":
            return log_check("Module import & system health", False, f"Health check returned {status}")
        return log_check("Module import & system health", True, f"v{__version__} verified healthy")
    except Exception as e:
        return log_check("Module import & system health", False, f"Import error: {e}")


def main() -> int:
    print("=" * 70)
    print("NetSage AI — Production Release & Quality Check")
    print("=" * 70)

    checks = [
        check_required_files(),
        check_dataset_integrity(),
        check_env_example_safety(),
        check_no_forbidden_execution_imports(),
        check_no_hardcoded_keys(),
        check_imports_and_health(),
    ]

    print("=" * 70)
    if all(checks):
        print("RESULT: ALL RELEASE ACCEPTANCE CHECKS PASSED [RELEASE-READY]")
        print("=" * 70)
        return 0
    else:
        print("RESULT: RELEASE CHECKS FAILED")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
