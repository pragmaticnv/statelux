# STATEFLUX — IPsec Security Change-Impact Intelligence

> **Current State → Change → Impact → Migration → Validation → Evidence**

**STATEFLUX** is an IPsec security intelligence and change-impact platform. It evaluates cryptographic fleet postures, determines dynamic negotiation floors, simulates proposed policy changes, isolates immediate and latent rekey outages, generates staged migration waves with automated rollback artifacts, and verifies predictions against controlled real-daemon testbeds.

---

## Core Product Statement

> **STATEFLUX predicts what happens before you change an IPsec security policy.**

In production IPsec networks, policy updates often appear successful initially while introducing dormant configuration defects. Hours or days later, when cryptographic lifetimes expire and daemons initiate `CREATE_CHILD_SA` rekeying, tunnels collapse unexpectedly. STATEFLUX eliminates this operational risk through deterministic simulation, Pareto-minimal floor gap analysis, and staged rollout sequencing.

---

## Capabilities & Architecture Pipeline

```text
Current State         Change              Impact               Migration            Validation           Evidence
┌──────────────┐     ┌──────────────┐    ┌────────────────┐   ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
│ Digital Twin │ ──> │ Proposed     │ ──>│ Blast Radius & │──>│ Phased Waves   │──>│ Controlled Lab │──>│ Multi-Source   │
│ Floor Matrix │     │ Policy CHG   │    │ Latent Outages │   │ Rollback Plans │   │ 5/5 Matched    │   │ Provenance     │
└──────────────┘     └──────────────┘    └────────────────┘   └────────────────┘   └────────────────┘   └────────────────┘
```

1. **Digital Twin & Security Floors:** Models 40 tunnels, 20 gateways, and 155 proposals across multi-vendor fleets (strongSwan, Libreswan, Cisco IOS-XE, FortiOS, JunOS, VyOS). Computes multidimensional Pareto security floors and downgrade gap vectors.
2. **Deterministic Change Simulator:** Evaluates prospective policy updates without live traffic risk, classifying outcomes into: `HARDENED`, `UNCHANGED`, `DEGRADED`, `INCOMPATIBLE`, `LATENT_FAILURE`, and `UNKNOWN`.
3. **Migration Planner & Waves:** Groups fleet transitions into topological stages (Canary, Regional, Core) with enforced preconditions, dependency ordering, and automated inverse rollback artifacts.
4. **Controlled Real-IPsec Testbed:** Containerized Linux network namespaces running real **strongSwan 5.9.8** and **Libreswan 4.12** daemons to empirically validate predictions.
   - **Validation Result:** **5/5 controlled testbed scenarios matched** across baseline negotiation, weak fallback, cipher mismatch, DH mismatch, and latent rekey failure.
5. **Evidence Engine & Provable Findings:** Binds findings to end-to-end provenance traces (`Configuration → Negotiation → Simulation → Lab Log → PCAP → Finding`).
6. **Command Center UI:** Dark-mode technical console featuring 2D Canvas negotiation graphs, live security floor inspector, blast radius heatmaps, and guided demo journey.
7. **Dedicated Report Export Architecture:** Standalone publication-grade export engine for Executive, Technical, Change-Impact, and Lab Validation audits in native vector PDF and clean printable HTML (zero application UI capture).

---

## Technology Stack

- **Backend:** Python 3.11, FastAPI, Pydantic v2, Uvicorn, Jinja2, ReportLab, AnyIO
- **Testing:** Pytest, Pytest-Asyncio, HTTPX TestClient (195 automated tests)
- **Frontend:** Vanilla JavaScript (ES2022+), CSS3 Design System, HTML5, HTML Canvas
- **Validation Testbed:** strongSwan 5.9.8, Libreswan 4.12, Linux Network Namespaces (`netns`), PCAP (`tcpdump`)

---

## Directory Structure

```text
stateflux/
├── backend/
│   ├── app/
│   │   ├── api/routes/          # REST route handlers (tunnels, security, simulation, reports)
│   │   ├── core/                # Configuration, security constants, rule catalog
│   │   ├── models/              # Canonical Pydantic v2 data models
│   │   ├── services/            # Simulation, floor, migration, lab, evidence, report engines
│   │   └── main.py              # FastAPI application bootstrap & lifespan loader
│   ├── tests/                   # 195 automated test cases
│   └── requirements.txt         # Backend Python dependencies
├── data/
│   ├── seed/                    # Authoritative fleet dataset (40 tunnels, 20 gateways)
│   └── scenarios/               # Scenario catalog
├── frontend/
│   ├── css/                     # Dark technical UI design system
│   ├── js/                      # Modular views (Command Center, Graph, Simulator, Reports)
│   └── index.html               # Single-page Command Center shell
├── lab/
│   ├── captures/                # Empirical PCAP packet capture artifacts
│   ├── configs/                 # strongSwan swanctl & Libreswan testbed configurations
│   └── logs/                    # Structured charon & pluto daemon telemetry
├── report_templates/            # Dedicated standalone report HTML templates
├── report_styles/               # Dedicated report print stylesheet (report.css)
├── docs/
│   └── reports/                 # Sample generated standalone PDF and HTML reports
├── scripts/
│   ├── generate_dataset.py      # Deterministic dataset generation utility
│   └── generate_sample_reports.py # Report generation verification utility
└── run.py                       # Application dev runner
```

---

## Getting Started

### 1. Environment Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/pragmaticnv/statelux.git
cd statelux
pip install -r backend/requirements.txt
```

### 2. Run the Test Suite

Execute the complete 195-test suite:

```bash
python -m pytest backend/tests
```

Expected result:
```text
======================= 195 passed, 2 warnings in 3.12s =======================
```

### 3. Launch Application

Start the local server:

```bash
python run.py
```

The application will start on `http://127.0.0.1:8000`:
- **Command Center UI:** [http://127.0.0.1:8000/ui](http://127.0.0.1:8000/ui)
- **API Documentation (Swagger UI):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **API Documentation (ReDoc):** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## Standalone Report Deliverables

STATEFLUX produces 4 dedicated standalone report types available at `/api/v1/reports/export/{type}/html` and `/api/v1/reports/export/{type}/pdf`:

1. **Executive Security Report** (`/reports/executive`)
2. **Technical IPsec Report** (`/reports/technical`)
3. **Change-Impact Report** (`/reports/change-impact`)
4. **Real IPsec Lab Validation Report** (`/reports/lab-validation`)

Sample pre-rendered reports are stored in [`docs/reports/`](docs/reports/).

---

## Controlled Lab & Empirical Validation

Predictions are evaluated against a reproducible testbed running real IPsec daemons:
- **Environment:** Linux Network Namespaces (`netns`), MTU 1500, UDP 500/4500
- **Daemons:** strongSwan 5.9.8 (`charon`), Libreswan 4.12 (`pluto`)
- **Scenarios Evaluated:**
  - `LAB-01`: Secure Suite-B Baseline (AES-256-GCM / DH20 / PFS) → **Matched**
  - `LAB-02`: Weak Functional Fallback (AES-128-CBC / DH14 / No PFS) → **Matched**
  - `LAB-03`: Encryption Incompatibility (AES-256-GCM vs AES-128-CBC) → **Matched**
  - `LAB-04`: Diffie-Hellman Mismatch (CURVE_384 vs MODP_2048) → **Matched**
  - `LAB-05`: Latent Rekey Failure (Uncoordinated cipher pruning) → **Matched**
- **Validation Score:** **5/5 controlled testbed scenarios matched**.

---

## Safety Scope & Limitations

- **Controlled Testbed Validation:** Results confirm agreement within containerized network namespaces under RFC 7296 and RFC 4303 protocol semantics. They do not constitute a statistical estimate of third-party production deployments.
- **Hardware & Vendor Quirks:** Proprietary hardware offload bugs, intermediary stateful firewall drops, or vendor-specific implementation quirks outside standard protocol definitions are not modeled in baseline simulations. Staged canary rollouts remain strictly mandatory.
- **Synthetic Fleet:** Initial demonstration dataset configurations are synthetically generated for benchmark evaluation.
