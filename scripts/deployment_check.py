from pathlib import Path
import ast
import importlib
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

required = [
    "app.py",
    "requirements.txt",
    "requirements.lock.txt",
    "cases.csv",
    "netsage",
    ".streamlit/config.toml",
]

errors = []
for item in required:
    if not (ROOT / item).exists():
        errors.append(f"Missing required path: {item}")

try:
    importlib.import_module("netsage")
except Exception as exc:
    errors.append(f"netsage import failed: {exc}")

forbidden = {"subprocess", "paramiko", "netmiko", "napalm", "fabric", "telnetlib"}
for path in ROOT.rglob("*.py"):
    if ".venv" in path.parts or "__pycache__" in path.parts or path == Path(__file__):
        continue
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError as exc:
        errors.append(f"Syntax error in {path.relative_to(ROOT)}: {exc}")
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module.split(".")[0]] if node.module else []
        else:
            continue
        for name in names:
            if name in forbidden:
                errors.append(f"Forbidden execution/network import '{name}' in {path.relative_to(ROOT)}")

if errors:
    print("DEPLOYMENT CHECK: FAIL")
    for error in errors:
        print(f"[FAIL] {error}")
    sys.exit(1)

print("DEPLOYMENT CHECK: PASS")
print("[PASS] Required application structure present")
print("[PASS] netsage package importable")
print("[PASS] Locked dependency manifest present")
print("[PASS] No forbidden device-execution imports detected")
print("[PASS] Ready for local/container launch")
