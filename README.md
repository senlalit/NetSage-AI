# NetSage AI: Cisco & Packet Tracer Network Troubleshooting Assistant

**Version:** `1.0.0`

> **Advisory & Read-Only System Guarantee**: NetSage AI is an advisory, read-only diagnostic intelligence system. It **does not** connect to, configure, or execute commands on network devices. All diagnostic proposals, single verification commands, and sequential fix steps are structured recommendations intended solely for qualified human network engineers.

---

## 1. Overview & Key Capabilities

NetSage AI provides AI-assisted, evidence-grounded troubleshooting for enterprise Cisco IOS and Packet Tracer network topologies. Built for Network Operations Centers (NOC), Security Operations Centers (SOC), and network engineering teams, NetSage AI combines deterministic protocol rules with large language model synthesis to diagnose network anomalies with zero hallucinations.

### Key Capabilities
- **Factual Protocol Rule Engine**: 28 deterministic protocol parsers analyzing OSPF, DHCP, ACL, NAT, VLAN, Trunking, Subnetting, Port Security, HSRP, CDP, and IPv6.
- **Evidence-Grounded AI Synthesis**: Generates root causes, single verification commands, and sequential fix steps strictly verified against provided telemetry.
- **Zero-Hallucination Grounding Validator**: Automatically rejects any AI output containing unsupported evidence claims.
- **Mandatory Human-in-the-Loop (HITL) Gate**: Complete Accept / Edit / Reject review station requiring human engineer sign-off.
- **Append-Only Responsible-AI Audit Ledger**: Atomic, immutable audit logging with before/after field-level diff calculation and compliance KPIs.
- **Offline-First & Air-Gapped**: Fully functional 100% offline out-of-the-box using the built-in deterministic provider, with optional Google Gemini Live API support.
- **Custom Cisco CLI Sandbox**: Safe, air-gapped simulation environment with input boundary protection.

---

## 2. System Architecture

```
+-----------------------------------------------------------------------------------+
|                                  cases.csv                                        |
|             (30 Authoritative Benchmark Cases NET-001 through NET-030)            |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                     Case Loader Service (netsage.case_loader)                     |
|                 • Project-relative dataset ingestion & validation                 |
|                 • Whitespace normalization without semantic mutation              |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|               Deterministic Diagnostic Engine (netsage.deterministic_engine)      |
|           • 28 Specialized rules covering OSPF, DHCP, ACL, NAT, VLAN, etc.        |
|           • Factual telemetry anomaly extraction directly from show-outputs        |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|               Evidence-Grounded AI Engine (netsage.ai_engine)                     |
|           • Offline Deterministic Provider (Default, 100% air-gapped)             |
|           • Google Gemini Live Provider (Optional via GEMINI_API_KEY)             |
|           • Strict benchmark ground truth isolation (expected_fault omitted)      |
|           • Automated Grounding Validator (validate_grounding)                    |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|            Mandatory Human-in-the-Loop Review Gate (netsage.audit_manager)        |
|           • ACCEPT: Approve AI proposal without modifications                     |
|           • EDIT: Correct proposal with live re-grounding & structured diff       |
|           • REJECT: Deny proposal with mandatory governance rejection reason      |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                Responsible-AI Audit Ledger & Governance Analytics                 |
|           • Immutable append-only storage in audit_log.json                       |
|           • Field-level diff computation & compliance metrics                     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                 NetSage Sentinel NOC Console Dashboard (app.py)                   |
|           1. Case Explorer     2. Diagnostic Console     3. Audit     4. Sandbox  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Safety & Responsible AI Architecture

1. **Air-Gapped Telemetry / Zero Device Execution**: NetSage AI contains **zero** SSH, Telnet, Netmiko, Paramiko, NAPALM, Fabric, subprocess, or shell execution capabilities.
2. **Ground Truth Isolation**: The benchmark reference `expected_fault` column is isolated exclusively for evaluation and is **never** passed into prompt templates or AI reasoning chains.
3. **Automated Evidence Grounding**: Every evidence string in an AI proposal is verified against the input symptom, topology note, and Cisco show command output. Ungrounded claims trigger an automatic rejection.
4. **Mandatory Human Review**: AI proposals are strictly advisory. Network changes can only be logged as approved through human engineer review (`ACCEPT`, `EDIT`, or `REJECT`).
5. **Secret Protection**: API keys are loaded strictly from the environment, automatically masked in logs (`SecretMaskingFilter`), and excluded from audit records.

---

## 4. Repository Structure

```text
NetSage AI/
├── app.py                      # Main NetSage Sentinel Streamlit NOC application
├── requirements.txt            # Production dependencies
├── README.md                   # Operator guide and technical documentation
├── .gitignore                  # Git exclusion rules (.env, audit logs, caches)
├── .env.example                # Safe environment template with placeholders
├── cases.csv                   # 30 Authoritative troubleshooting benchmark cases
├── .streamlit/
│   └── config.toml             # Streamlit server and dark NOC theme tokens
├── netsage/                    # Core NetSage AI Python package
│   ├── __init__.py             # Package exports, version (v1.0.0), and dotenv loader
│   ├── models.py               # Pydantic data schemas (NetworkCase, AIDiagnosis, etc.)
│   ├── case_loader.py          # CSV ingestion, normalization, and validation
│   ├── deterministic_engine.py # 28 Cisco protocol anomaly detection rules
│   ├── prompt_templates.py     # Grounded AI prompts with expected_fault isolation
│   ├── ai_engine.py            # AI Engine with Offline and Gemini providers
│   ├── audit_manager.py        # Atomic persistence, edit diffs, and audit metrics
│   ├── ui_components.py        # NetSage Sentinel UI tokens, cards, and CSS
│   ├── logging_config.py       # Structured logging with secret masking filter
│   └── system_health.py        # Non-secret system health validation service
├── tests/                      # Automated test suite (64 tests)
│   ├── test_case_loader.py
│   ├── test_deterministic_engine.py
│   ├── test_ai_engine.py
│   ├── test_audit_manager.py
│   ├── test_app_helpers.py
│   ├── test_streamlit_app.py
│   ├── test_security_hardening.py
│   ├── test_configuration.py
│   └── test_error_handling.py
└── scripts/
    └── release_check.py        # Automated release & productization verification check
```

---

## 5. Installation & Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Git

### Installation Steps
```bash
# 1. Clone or navigate to the repository
cd "NetSage AI"

# 2. Create and activate a Python virtual environment
python -m venv .venv

# Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Linux / macOS:
source .venv/bin/activate

# 3. Install required dependencies
pip install -r requirements.txt
```

---

## 6. Configuration & Operating Modes

Copy `.env.example` to create your local `.env`:

```bash
cp .env.example .env
```

### Configuration Options (`.env`)
```env
# Google Gemini API Key (Optional)
# Leave empty to operate 100% offline using the built-in Deterministic Engine.
GEMINI_API_KEY=your_gemini_api_key_here

# Streamlit Server Configuration (Optional)
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_HEADLESS=true
NETSAGE_LOG_LEVEL=INFO
```

### Operating Modes
- **Offline Deterministic Mode (Default)**: If `GEMINI_API_KEY` is not provided, NetSage AI operates completely air-gapped without making any external network or API calls.
- **Optional Gemini Live Mode**: If `GEMINI_API_KEY` is provided, operators can optionally switch to the Gemini Provider for live generative synthesis with schema validation.

---

## 7. Launching the Application

Launch the NetSage Sentinel dashboard with a single command:

```bash
streamlit run app.py
```

Or using the virtual environment interpreter explicitly:
```bash
python -m streamlit run app.py --server.headless true --server.port 8501
```

Access the dashboard at `http://localhost:8501`.

---

## 8. Application Views

1. **📋 Case Explorer**: Filter and inspect the 30 benchmark cases (`NET-001` through `NET-030`) by Severity, OSI Layer, and Concept Tag. Ground-truth `expected_fault` is strictly partitioned for evaluation.
2. **🔍 Diagnostic & HITL Console**: Execute deterministic checks and AI synthesis. Review the root cause, OSI layer, confidence gauge, grounded evidence quotes, single verification command, and recommended fix steps. Complete the review through the **ACCEPT**, **EDIT**, or **REJECT** station.
3. **📊 Audit & Governance Analytics**: Real-time governance KPIs (Acceptance Rate, AI Correction Rate, Rejection Rate, Average Confidence) and searchable immutable audit trail with before/after diff cards.
4. **🧪 Custom Cisco CLI Sandbox**: Air-gapped testing sandbox for custom or anonymized Cisco IOS telemetry with input size limits.

---

## 9. 5-Minute Demonstration Walkthrough

Follow these 10 steps for a complete product demonstration:

- **STEP 1 — Open Case Explorer**: Navigate to `http://localhost:8501` and click the **📋 Case Explorer** tab.
- **STEP 2 — Select Benchmark Case**: Choose case `NET-001` from the dropdown list.
- **STEP 3 — Inspect Telemetry**: Review the symptom (`PC1 cannot reach Server1 in VLAN 30`), topology note (`Gateway on Router Sub-interface Gi0/0.10`), and raw Cisco show-output (`GigabitEthernet0/0.10 is administratively down`).
- **STEP 4 — Open Diagnostic Console**: Switch to the **🔍 Diagnostic & HITL Console** tab. Case `NET-001` is pre-loaded.
- **STEP 5 — Run AI Diagnosis**: Click **Execute Telemetry Checks & AI Diagnosis**.
- **STEP 6 — Review Diagnostic Proposal**: Inspect the deterministic finding (`Interface GigabitEthernet0/0.10 is administratively down`), synthesized root cause, OSI Layer (`Layer 3`), confidence score, grounded evidence, single verification command (`show ip interface brief`), and sequential fix steps.
- **STEP 7 — Authorize Review (ACCEPT)**: In the Human Review Station, select **ACCEPT**, enter optional reviewer notes (`Approved for maintenance window`), and click **Approve & Commit to Audit Ledger (ACCEPT)**.
- **STEP 8 — Open Audit & Governance Analytics**: Switch to the **📊 Audit & Governance Analytics** tab.
- **STEP 9 — Inspect Audit Trail**: Observe the updated KPI metrics and inspect the newly created immutable audit record (`AUD-...`) capturing the case ID, timestamp, original AI diagnosis, human decision, and final approved output.
- **STEP 10 — Test Custom CLI Sandbox**: Switch to the **🧪 Custom Cisco CLI Sandbox** tab. Paste custom Cisco show-output (see sample below) and click **Analyze Telemetry & Synthesize Diagnosis** to view air-gapped analysis.

---

## 10. Sample Safe Sandbox Data

Use the following safe sample telemetry in the Custom CLI Sandbox:

```text
======================================================================
DEMO DATA — NOT EXECUTED (Read-Only Telemetry Simulation)
======================================================================

Symptom:
Branch office PC cannot reach corporate intranet web portal.

Topology Note:
Branch Router R1 Gi0/1 (192.168.1.1/24); Core Switch SW1 on VLAN 10.

Show Outputs:
Router# show ip interface brief
Interface                  IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0         10.0.0.1        YES NVRAM  up                    up      
GigabitEthernet0/1         192.168.1.1     YES manual administratively down down    
Loopback0                  1.1.1.1         YES manual up                    up      

Router# show running-config interface Gi0/1
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 shutdown
!
```

---

## 11. Automated Testing & Quality Checks

### Run All Unit and Integration Tests
```bash
pytest -v
```

### Run the Product Release Check Script
```bash
python scripts/release_check.py
```

### Validate Syntax & Compilation
```bash
python -m py_compile app.py netsage/*.py scripts/release_check.py
```

---

## 12. Troubleshooting & FAQ

- **Q: What if I don't have a Gemini API Key?**
  - NetSage AI automatically uses the built-in `OfflineDeterministicProvider`. All 30 benchmark cases, deterministic rules, HITL reviews, and audit logs work 100% offline without any API key.
- **Q: Does NetSage AI connect to my live routers or switches?**
  - No. NetSage AI is an air-gapped advisory system. It parses text telemetry provided by the operator and outputs structured recommendations. No network sockets or SSH connections are created.
- **Q: What happens if an edit introduces ungrounded evidence?**
  - The grounding validation engine detects ungrounded claims during human edit review and raises an error, ensuring data integrity in the audit ledger.

---

## 13. System Status Metadata

When running, the application sidebar displays:
- **Version**: `1.0.0`
- **Data Layer**: `OK (30 Cases)`
- **Deterministic Engine**: `28 Rules Active`
- **AI Engine**: `Offline Deterministic` (or `Gemini API & Offline`)
- **Audit Ledger**: `Append-Only`
- **Safety Mode**: `🔒 READ-ONLY MODE (Advisory Only)`

---

## 14. License & Authoritative Reference

NetSage AI is developed in compliance with the Cisco Network Diagnostic Benchmark Specification. Authoritative dataset: `cases.csv`.
