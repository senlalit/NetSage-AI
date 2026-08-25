# NetSage AI: Cisco & Packet Tracer Network Troubleshooting Assistant

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/Tests-64%2F64%20Passing-success?style=for-the-badge&logo=pytest&logoColor=white)](file:///c:/Users/pc/Downloads/NetSage_AI/tests)
[![Responsible AI](https://img.shields.io/badge/Responsible%20AI-HITL%20%2B%20Audit%20Ledger-8A2BE2?style=for-the-badge)](file:///c:/Users/pc/Downloads/NetSage_AI/netsage/audit_manager.py)
[![Security](https://img.shields.io/badge/Safety-Air--Gapped%20%26%20Read--Only-green?style=for-the-badge)](file:///c:/Users/pc/Downloads/NetSage_AI/netsage)

**Version:** `1.0.0` | **License:** MIT / Enterprise Benchmark Spec

</div>

---

> [!IMPORTANT]
> **Advisory & Read-Only System Guarantee**: NetSage AI is an advisory, read-only diagnostic intelligence platform. It **does not** connect to, configure, or execute commands on live network devices. All root cause analyses, single verification commands, and sequential fix steps are structured recommendations intended solely for qualified human network engineers.

---

## 📑 Table of Contents

- [1. Overview \& Core Capabilities](#1-overview--core-capabilities)
- [2. System Architecture](#2-system-architecture)
- [3. Safety \& Responsible AI Framework](#3-safety--responsible-ai-framework)
- [4. Repository Structure](#4-repository-structure)
- [5. Installation \& Setup](#5-installation--setup)
  - [Local Virtual Environment (.venv)](#local-virtual-environment-venv)
  - [Ready-to-Use Windows Scripts](#ready-to-use-windows-scripts)
  - [Docker \& Docker Compose](#docker--docker-compose)
  - [VS Code Dev Containers](#vs-code-dev-containers)
- [6. Configuration \& Operating Modes](#6-configuration--operating-modes)
- [7. Application Views \& Features](#7-application-views--features)
- [8. Cisco Packet Tracer Lab Integration](#8-cisco-packet-tracer-lab-integration)
- [9. Step-by-Step 5-Minute Demonstration](#9-step-by-step-5-minute-demonstration)
- [10. Quality Assurance, Testing \& Healthchecks](#10-quality-assurance-testing--healthchecks)
- [11. Benchmark Dataset (NET-001 to NET-030)](#11-benchmark-dataset-net-001-to-net-030)
- [12. Troubleshooting \& FAQ](#12-troubleshooting--faq)

---

## 1. Overview & Core Capabilities

**NetSage AI** provides AI-assisted, evidence-grounded troubleshooting for enterprise Cisco IOS and Cisco Packet Tracer network topologies. Built for Network Operations Centers (NOC), Security Operations Centers (SOC), and network engineering teams, NetSage AI blends deterministic protocol analysis with large language model synthesis to diagnose network anomalies with **zero hallucinations**.

### Key Capabilities
- **28 Deterministic Protocol Parsers**: Deep deterministic rules covering OSPF, DHCP, ACL, NAT, VLAN, 802.1Q Trunking, Subnetting, Port Security, HSRP, CDP, and IPv6.
- **Evidence-Grounded AI Engine**: Synthesizes human-readable root causes, single verification commands, and sequential fix steps strictly verified against provided telemetry.
- **Zero-Hallucination Grounding Validator**: Automatically verifies every quoted evidence token against the input telemetry, rejecting ungrounded or speculative statements.
- **Mandatory Human-in-the-Loop (HITL) Review Gate**: Complete `ACCEPT`, `EDIT`, and `REJECT` workflows with live structured diff generation for human review.
- **Append-Only Responsible-AI Audit Ledger**: Atomic, immutable audit logging (`audit_log.json`) tracking every diagnosis, human modification, and compliance metric.
- **100% Air-Gapped & Offline Default**: Works out of the box with zero internet connectivity using the built-in deterministic provider, with optional Google Gemini Live API support.
- **Custom Cisco CLI Sandbox**: Real-time diagnostic console allowing operators to paste arbitrary Cisco `show` command outputs for immediate evaluation.
- **Cisco Packet Tracer Lab**: Includes `.pkt` topology files and native Cisco IOS device configuration scripts (`.cfg`).

---

## 2. System Architecture

```mermaid
flowchart TD
    A[cases.csv / Custom CLI Telemetry] --> B[netsage.case_loader]
    B --> C[netsage.deterministic_engine\n28 Protocol Rules]
    C --> D[netsage.ai_engine\nOffline / Gemini Live]
    D --> E{netsage.ai_engine\nvalidate_grounding}
    E -- Grounding Passed --> F[netsage.audit_manager\nHuman-in-the-Loop Review Station]
    E -- Ungrounded --> G[Rejection / Fallback]
    F -- ACCEPT / EDIT / REJECT --> H[(audit_log.json\nAtomic Append-Only Ledger)]
    H --> I[Streamlit Sentinel UI\n1. Explorer | 2. Console | 3. Audit | 4. Sandbox]
```

### Architectural Pipeline
1. **Case Ingestion Layer (`netsage.case_loader`)**: Loads and validates the 30 benchmark cases (`cases.csv`) with strict whitespace normalization and data schema validation.
2. **Deterministic Protocol Engine (`netsage.deterministic_engine`)**: Evaluates 28 protocol-specific rule checkers against show-command telemetry, extracting deterministic findings.
3. **AI Diagnostic Engine (`netsage.ai_engine`)**: Dispatches telemetry to either the `OfflineDeterministicProvider` (default) or `GeminiLiveProvider`.
4. **Grounding Validator (`validate_grounding`)**: Enforces strict grounding checks to guarantee that every piece of cited evidence exists verbatim in the case telemetry.
5. **Human-in-the-Loop Review Gate (`netsage.audit_manager`)**: Captures operator decisions (`ACCEPT`, `EDIT`, or `REJECT`) along with reviewer notes, rejection justifications, and field-level diffs.
6. **Responsible-AI Audit Ledger (`audit_log.json`)**: Thread-safe, atomic disk persistence calculating compliance KPIs (acceptance rate, correction rate, rejection rate).
7. **NetSage Sentinel UI (`app.py`)**: Modern NOC dashboard styled with high-contrast cybersecurity aesthetics.

---

## 3. Safety & Responsible AI Framework

1. **Air-Gapped Telemetry / Zero Device Execution**:
   NetSage AI contains **zero** SSH, Telnet, Netmiko, Paramiko, NAPALM, Fabric, subprocess, or shell execution capabilities. It strictly acts on text telemetry.
2. **Ground Truth Isolation**:
   The benchmark reference `expected_fault` column in `cases.csv` is strictly isolated for evaluation and is **never** passed into AI prompts or reasoning chains.
3. **Automated Evidence Grounding**:
   Every evidence quote generated by AI or submitted by a human reviewer is strictly validated against the input symptom, topology note, and Cisco show-command outputs.
4. **Mandatory Human Sign-Off**:
   AI outputs are purely advisory. Remediation steps can only be logged as approved through conscious human engineer review.
5. **Secret Protection & Logging Masking**:
   All API keys and credentials are automatically masked by `SecretMaskingFilter` and are never written to disk or audit logs.

---

## 4. Repository Structure

```text
NetSage_AI/
├── .devcontainer/
│   └── devcontainer.json           # VS Code Remote Container configuration
├── .streamlit/
│   └── config.toml                 # Dark NOC theme tokens and server settings
├── netsage/                        # Core NetSage AI Python Package
│   ├── __init__.py                 # Package exports, version (v1.0.0), environment loader
│   ├── models.py                   # Pydantic data schemas (NetworkCase, AIDiagnosis, etc.)
│   ├── case_loader.py              # CSV ingestion, normalization, and validation
│   ├── deterministic_engine.py     # 28 Cisco protocol anomaly detection rules
│   ├── prompt_templates.py         # Grounded AI prompts with expected_fault isolation
│   ├── ai_engine.py                # AI Engine with Offline and Gemini providers
│   ├── audit_manager.py            # Atomic persistence, edit diffs, and audit metrics
│   ├── ui_components.py            # NOC UI tokens, status badges, diff cards, CSS
│   ├── logging_config.py           # Structured logging with secret masking filter
│   └── system_health.py            # Non-secret system health validation service
├── packet_tracer_lab/              # Cisco Packet Tracer Lab Assets
│   ├── PACKET_TRACER_LAB_GUIDE.md  # Comprehensive lab build and wiring guide
│   ├── R1_base.cfg                 # Router R1 (Core Gateway) baseline config
│   ├── R2_base.cfg                 # Router R2 (Branch Router) baseline config
│   ├── SW1_base.cfg                # Switch SW1 (Distribution) baseline config
│   └── SW2_base.cfg                # Switch SW2 (Access) baseline config
├── scripts/                        # Automation & Health Scripts
│   ├── container_healthcheck.py    # Docker container health probe
│   ├── deployment_check.py         # Pre-deployment validation script
│   └── release_check.py            # Product release & compliance acceptance gate
├── tests/                          # Full Automated Test Suite (64 tests)
│   ├── test_ai_engine.py
│   ├── test_app_helpers.py
│   ├── test_audit_manager.py
│   ├── test_case_loader.py
│   ├── test_configuration.py
│   ├── test_deterministic_engine.py
│   ├── test_error_handling.py
│   ├── test_security_hardening.py
│   └── test_streamlit_app.py
├── .env.example                    # Template for environment variables
├── .gitignore                      # Git exclusion rules
├── app.py                          # Streamlit NOC Dashboard Application
├── audit_log.json                  # Append-only immutable audit ledger records
├── cases.csv                       # 30 Authoritative troubleshooting benchmark cases
├── Dockerfile                      # Production multi-stage Docker container
├── docker-compose.yml              # Docker Compose service definition
├── NetSage_AI_Enterprise_Lab.pkt   # Cisco Packet Tracer topology file
├── PHASE_8_DEPLOYMENT.md           # Deployment operations specification
├── requirements.lock.txt           # Pinned production dependencies
├── requirements.txt                # Core production dependencies
├── run_netsage.bat                 # One-click Windows PowerShell/CMD runner
└── run_netsage_docker.bat          # One-click Docker Compose runner
```

---

## 5. Installation & Setup

### Local Virtual Environment (`.venv`)

#### Windows (PowerShell)
```powershell
# 1. Clone the repository
git clone https://github.com/senlalit/NetSage-AI.git
cd NetSage-AI

# 2. Create and activate virtual environment
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Launch NetSage AI
streamlit run app.py
```

#### Linux / macOS
```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Launch NetSage AI
streamlit run app.py
```

---

### Ready-to-Use Windows Scripts

- **Native Python Launch**: Double-click [`run_netsage.bat`](file:///c:/Users/pc/Downloads/NetSage_AI/run_netsage.bat) or run `.\run_netsage.bat`.
- **Docker Compose Launch**: Double-click [`run_netsage_docker.bat`](file:///c:/Users/pc/Downloads/NetSage_AI/run_netsage_docker.bat) or run `.\run_netsage_docker.bat`.

---

### Docker & Docker Compose

Run NetSage AI in an isolated container:

```bash
# Build and start the container
docker compose up --build -d

# View container logs
docker compose logs -f

# Stop the container
docker compose down
```

Access the application at `http://localhost:8501`.

---

### VS Code Dev Containers

This repository includes a ready-to-use Dev Container configuration (`.devcontainer/devcontainer.json`).
1. Open the project folder in **VS Code**.
2. When prompted, click **"Reopen in Container"** (or open the Command Palette `Ctrl+Shift+P` and select `Dev Containers: Reopen in Container`).
3. Dependencies and environment will automatically initialize.

---

## 6. Configuration & Operating Modes

Copy the example environment template:

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
- **Offline Deterministic Mode (Default)**: When `GEMINI_API_KEY` is omitted, NetSage AI operates completely air-gapped without making external network calls.
- **Gemini Live Mode**: When `GEMINI_API_KEY` is provided, operators can enable the Gemini Provider for generative synthesis with schema validation.

---

## 7. Application Views & Features

### 📋 1. Case Explorer
- Browse all 30 benchmark cases (`NET-001` through `NET-030`).
- Filter by **Severity** (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), **OSI Layer** (`Layer 1` to `Layer 7`), and **Concept Tag**.
- Inspect raw telemetry, symptoms, and topology notes while ground truth `expected_fault` is safely isolated.

### 🔍 2. Diagnostic & HITL Console
- Execute deterministic protocol checks and AI synthesis.
- View structured root cause analysis, confidence gauge, verbatim grounded evidence quotes, single verification commands, and sequential remediation steps.
- Complete the mandatory human review using the **ACCEPT**, **EDIT**, or **REJECT** station.

### 📊 3. Audit & Governance Analytics
- Real-time compliance KPIs: **Total Reviews**, **Acceptance Rate**, **AI Correction Rate**, **Rejection Rate**, and **Average Confidence**.
- Visual distribution bar charts: **Decisions by OSI Layer** and **Reviews by Case Severity**.
- Searchable, immutable audit ledger table with deep-dive inspection showing full before/after JSON diffs.

### 🧪 4. Custom Cisco CLI Sandbox
- Test arbitrary, unbenchmarked Cisco IOS show-command telemetry.
- Safe input boundary protection with automated protocol analysis.

---

## 8. Cisco Packet Tracer Lab Integration

The repository includes a complete enterprise lab topology modeled in Cisco Packet Tracer:

- **Topology File**: [`NetSage_AI_Enterprise_Lab.pkt`](file:///c:/Users/pc/Downloads/NetSage_AI/NetSage_AI_Enterprise_Lab.pkt)
- **Lab Guide**: [PACKET_TRACER_LAB_GUIDE.md](file:///c:/Users/pc/Downloads/NetSage_AI/packet_tracer_lab/PACKET_TRACER_LAB_GUIDE.md)
- **Device Baseline Configurations**:
  - `R1_base.cfg` (Core Router / Router-on-a-Stick Gateway)
  - `R2_base.cfg` (Branch Router / OSPF Area 0)
  - `SW1_base.cfg` (Distribution Catalyst 2960 Switch)
  - `SW2_base.cfg` (Access Catalyst 2960 Switch)

```text
                        +--------------------+
                        |     Router R1      |
                        |   Core / Gateway   |
                        +---------+----------+
                                  | Gi0/1 (10.0.0.1/30)
                                  |
                                  | Gi0/0 (10.0.0.2/30)
                                  v
                        +--------------------+
                        |     Router R2      |
                        |   Branch Router    |
                        +---------+----------+
                                  | Gi0/1
                                  v
                        [ Remote Server 10.0.0.130 ]
                                  ^
                                  | (OSPF Area 0)
        +-------------------------+-------------------------+
        | Gi0/0 (802.1Q Sub-interfaces .10, .20, .30, .40)
        v
+----------------+      Fa0/24 (Trunk)      +----------------+
|   Switch SW1   |<=======================>|   Switch SW2   |
| Catalyst 2960  |                         | Catalyst 2960  |
+---+-----+------+                         +-------+--------+
    |     |     |                                  |
Fa0/1| Fa0/2| Fa0/10|                              | Fa0/5
    |     |     |                                  |
    v     v     v                                  v
 [PC1]  [PC2] [Finance PC]                    [Server 1]
(VLAN10) (VLAN20) (VLAN40)                     (VLAN30)
```

---

## 9. Step-by-Step 5-Minute Demonstration

1. **Launch App**: Start the dashboard and open `http://localhost:8501`.
2. **Explore Case**: Select **📋 1. Case Explorer** and choose case `NET-001`.
3. **Inspect Telemetry**: Notice that `GigabitEthernet0/0.10 is administratively down`.
4. **Run Diagnosis**: Switch to **🔍 2. Diagnostic & HITL Console** and click **Execute Telemetry Checks & AI Diagnosis**.
5. **Review Output**: Inspect the detected anomaly, confidence score (`96%`), grounded evidence, and recommended remediation commands (`no shutdown`).
6. **Accept Review**: In the HITL station, select **ACCEPT**, add reviewer notes, and submit.
7. **Inspect Audit Ledger**: Open **📊 3. Audit & Analytics** to observe the updated compliance KPIs, OSI layer charts, and immutable audit record.
8. **Test Sandbox**: Open **🧪 4. Custom CLI Sandbox**, paste custom show-output, and run real-time diagnostic evaluation.

---

## 10. Quality Assurance, Testing & Healthchecks

NetSage AI includes an automated test suite with **64 passing tests** across 9 test modules:

```bash
# Run full unit and integration test suite
pytest -v

# Run product release & compliance verification
python scripts/release_check.py

# Run pre-deployment environment check
python scripts/deployment_check.py

# Run Docker container health probe
python scripts/container_healthcheck.py

# Validate syntax compilation across all files
python -m py_compile app.py netsage/*.py scripts/*.py
```

---

## 11. Benchmark Dataset (NET-001 to NET-030)

The system includes 30 benchmark network fault cases (`cases.csv`):

| Case ID | Protocol / Technology | Severity | OSI Layer | Scenario Summary |
| :--- | :--- | :--- | :--- | :--- |
| `NET-001` | Interface Management | HIGH | Layer 3 | Sub-interface administratively shutdown |
| `NET-002` | VLAN Configuration | CRITICAL | Layer 2 | Access port assigned to non-existent VLAN |
| `NET-003` | 802.1Q Trunking | CRITICAL | Layer 2 | Native VLAN mismatch across trunk link |
| `NET-004` | DHCP Services | HIGH | Layer 7 | DHCP pool exhaustion on local router |
| `NET-005` | IPv4 Subnetting | HIGH | Layer 3 | IP address subnet mask mismatch |
| `NET-006` | Static Routing | CRITICAL | Layer 3 | Next-hop IP unreachable / incorrect gateway |
| `NET-007` | OSPF Routing | CRITICAL | Layer 3 | OSPF Hello / Dead timer mismatch |
| `NET-008` | OSPF Area Config | CRITICAL | Layer 3 | Area ID mismatch preventing adjacency |
| `NET-009` | Access Control Lists | HIGH | Layer 4 | Implicit deny blocking legitimate HTTP/DNS |
| `NET-010` | Standard ACL | HIGH | Layer 3 | ACL applied in wrong direction on gateway |
| `NET-011` | NAT Overload (PAT) | CRITICAL | Layer 3 | NAT pool exhausted / missing overload keyword |
| `NET-012` | Static NAT | HIGH | Layer 3 | Inside global address mapped incorrectly |
| `NET-013` | Port Security | HIGH | Layer 2 | MAC violation shutdown trigger |
| `NET-014` | Spanning Tree (STP) | CRITICAL | Layer 2 | Root bridge priority misconfiguration |
| `NET-015` | HSRP Redundancy | HIGH | Layer 3 | Virtual IP mismatch between routers |
| `NET-016` | CDP Discovery | LOW | Layer 2 | CDP disabled on critical trunk interface |
| `NET-017` | DNS Resolution | MEDIUM | Layer 7 | Incorrect DNS server IP provided by DHCP |
| `NET-018` | NTP Synchronization | LOW | Layer 7 | NTP server unreachable / stratum desync |
| `NET-019` | SSH Management | MEDIUM | Layer 7 | Transport input missing SSH configuration |
| `NET-020` | Dynamic Trunking (DTP)| HIGH | Layer 2 | DTP negotiation mode mismatch (access/trunk) |
| `NET-021` | Duplex / Speed | MEDIUM | Layer 1 | Duplex mismatch causing late collisions |
| `NET-022` | MTU Mismatch | HIGH | Layer 3 | OSPF stuck in EXSTART due to MTU size mismatch|
| `NET-023` | IPv6 SLAAC | HIGH | Layer 3 | Router Advertisements suppressed on link |
| `NET-024` | IPv6 Static Route | HIGH | Layer 3 | Invalid link-local next-hop without interface |
| `NET-025` | VTP Domain | HIGH | Layer 2 | VTP domain name / password mismatch |
| `NET-026` | EtherChannel (LACP) | CRITICAL | Layer 2 | Channel-group mode mismatch (active/passive) |
| `NET-027` | BGP Neighbor Peering | CRITICAL | Layer 3 | Remote AS number misconfiguration |
| `NET-028` | Router-on-a-Stick | CRITICAL | Layer 3 | Missing 802.1Q encapsulation on sub-interface |
| `NET-029` | IP Helper-Address | HIGH | Layer 3 | Missing DHCP relay agent on branch router |
| `NET-030` | Default Route | CRITICAL | Layer 3 | Missing default quad-zero route to ISP |

---

## 12. Troubleshooting & FAQ

#### Q: How do I run NetSage AI completely offline without internet or API keys?
**A:** Simply launch the app (`streamlit run app.py` or `run_netsage.bat`) without specifying a `GEMINI_API_KEY`. The built-in `OfflineDeterministicProvider` provides 100% air-gapped analysis.

#### Q: Why did the audit ledger show 0 records after deploying to Streamlit Cloud?
**A:** The audit ledger is stored in `audit_log.json`. Ensure `audit_log.json` is committed and pushed to your GitHub repository. The app will automatically initialize with the included records.

#### Q: Does NetSage AI execute configuration changes on devices?
**A:** **No.** NetSage AI is an advisory diagnostic tool. It does not contain device interaction libraries (SSH/Telnet/Netmiko). Network engineers must manually review and apply any recommended commands.

#### Q: How does grounding validation prevent AI hallucinations?
**A:** `netsage.ai_engine.validate_grounding` checks every cited evidence quote against the raw input telemetry. If an AI proposal cites an unobserved IP or interface state, it is rejected automatically.

---

<div align="center">

**NetSage AI — Evidence-Grounded Diagnostic Intelligence for Cisco Networks**  
*Advisory • Air-Gapped • Responsible AI • Zero Hallucinations*

</div>
