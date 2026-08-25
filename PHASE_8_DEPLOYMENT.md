# NetSage AI — Phase 8 Deployment & Operations

## Scope

Phase 8 packages the existing NetSage AI v1.0.0 Streamlit application for reproducible local and Docker deployment.

The deployment preserves the existing safety architecture:

- deterministic diagnostics
- evidence-grounded AI diagnosis
- mandatory human-in-the-loop review
- immutable auditability
- advisory/read-only operation
- zero direct network-device execution

## Local Windows launch

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
.venv\Scripts\python.exe scripts/deployment_check.py
.venv\Scripts\python.exe -m py_compile app.py netsage/*.py scripts/*.py
.venv\Scripts\python.exe -m pytest -v
.venv\Scripts\python.exe -m streamlit run app.py --server.headless true --server.port 8501
```

Or use `run_netsage.bat`.

Open `http://localhost:8501`.

## Docker launch

Requirements: Docker Desktop with Compose.

```powershell
docker compose up --build
```

Open `http://localhost:8501`.

Gemini is optional. If `GEMINI_API_KEY` is absent, the application remains in offline mode. To supply a key to Compose, set it in the shell or keep it in a local `.env` file that is never committed.

## Health check

The container checks Streamlit's local `/_stcore/health` endpoint. This is a local process-health check and does not contact network devices or external AI services.

## Security boundaries

The deployment does not add:

- SSH
- Telnet
- Netmiko
- Paramiko
- NAPALM
- Fabric
- shell/device command execution
- autonomous remediation

AI verification commands and fix steps remain advisory text. A human operator must manually decide whether to apply any action.

## Release verification

Run:

```powershell
.venv\Scripts\python.exe scripts/deployment_check.py
.venv\Scripts\python.exe scripts/release_check.py
.venv\Scripts\python.exe -m pytest -v
```

The release check and full regression suite remain the final acceptance gates.

## Packet Tracer phase

Phase 8 deliberately packages the current application first. The subsequent `.pkt` phase will model the 30 benchmark network scenarios in Cisco Packet Tracer and use NetSage AI as the advisory diagnostic layer.
