# STATEFLUX — DEMO FREEZE

**Release Target:** Smart India Hackathon (SIH) Final Demonstration  
**Platform Version:** STATEFLUX 1.0.0-final  
**Baseline Test Count:** **186 passed, 0 failed, 0 errors**  
**Freeze Status:** **HARD CODE FREEZE ACTIVE**  
**Freeze Timestamp:** 2026-09-29T20:05:00+05:30  

---

## 1. Executive Demonstration Credentials

| Attribute | Deployment Target |
| :--- | :--- |
| **Command Center UI** | `http://127.0.0.1:8000/ui` |
| **Interactive API Documentation** | `http://127.0.0.1:8000/docs` |
| **OpenAPI Specification** | `http://127.0.0.1:8000/openapi.json` |
| **Alternative Docs (ReDoc)** | `http://127.0.0.1:8000/redoc` |
| **Architecture** | Single-process ASGI FastAPI backend with integrated zero-dependency Command Center frontend |

---

## 2. Application Startup & Operation

### Standard Startup Command
From the project root directory (`N:\CODING\stateflux`):

```powershell
python run.py
```

### Emergency / Clean Background Startup
If port 8000 is occupied or you need to launch cleanly from a fresh shell:

```powershell
# 1. Terminate any previous instance
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force

# 2. Launch STATEFLUX server
python run.py
```

Console Output Verification:
```text
============================================================
STATEFLUX — AI-Assisted IPsec Intelligence Platform
Starting server on http://127.0.0.1:8000
API Documentation: http://127.0.0.1:8000/docs
Command Center:    http://127.0.0.1:8000/ui
============================================================
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Dataset ready: 40 tunnels | 20 endpoints | 155 proposals
```

---

## 3. Controlled Testbed Lab Requirements

- **Runtime Architecture:** Isolated Linux container netns namespace or pre-recorded empirical testbed artifacts.
- **VPN Daemons:** strongSwan 5.9.11 (`charon`) & Libreswan 4.x (`pluto`).
- **Cryptographic Testbed Scenarios:** 5 standardized validation scenarios:
  1. `LAB-01`: Modern Suite-B baseline (`strongSwan <-> strongSwan`, AES-256-GCM / DH20 / PFS) -> **ESTABLISHED**
  2. `LAB-02`: Weak legacy fallback (`strongSwan <-> strongSwan`, AES-128-CBC / DH14) -> **ESTABLISHED (WEAK)**
  3. `LAB-03`: Cipher incompatibility (`strongSwan <-> Libreswan`, AES-GCM only vs CBC only) -> **FAILED**
  4. `LAB-04`: Diffie-Hellman group mismatch (`strongSwan <-> strongSwan`, DH19 vs DH14) -> **FAILED**
  5. `LAB-05`: Latent rekey proposal failure (`strongSwan <-> Libreswan`, rekey drops SA) -> **LATENT_FAILURE**
- **Testbed Agreement:** 5/5 controlled testbed scenarios matched (100% testbed agreement rate).

---

## 4. Canonical 12-Step Judge Demonstration Script

To present the complete STATEFLUX story without deviation, follow this sequence:

```text
TODAY
  ↓
WHAT IF I REMOVE WEAK CRYPTO?
  ↓
WHAT BREAKS?
  ↓
HOW MANY TUNNELS?
  ↓
WHICH ONES?
  ↓
IN WHAT ORDER SHOULD I MIGRATE?
  ↓
CAN STATEFLUX PREDICT THE FAILURE?
  ↓
DID THE REAL IPsec LAB AGREE?
  ↓
WHAT EVIDENCE SUPPORTS THAT?
```

### Demonstration Steps:

1. **Step 1 — Command Center (`#/command-center`):**
   - Point out the core statement: *"Know what happens before you change the VPN."*
   - Highlight dynamic fleet posture: 20 Gateways, 40 Tunnels, 11 Hardened, 17 Unchanged, 7 Incompatible, 3 Latent Failure, 2 Unknown.
2. **Step 2 — Fleet Negotiation Graph (`#/graph`):**
   - Show the 20-gateway topology. Click a core hub gateway node to show neighbor connectivity and connected tunnels.
3. **Step 3 — Security Floor Intelligence (`#/security-floors` or `#detail-drawer`):**
   - Highlight the multidimensional gap: Selected Proposal (`AES-256-GCM / DH20 / PFS`) vs Permitted Floor (`3DES / DH14 / NO-PFS`).
   - Explain: *"A tunnel that appears secure today will silently downgrade tomorrow because the permissive floor permits weak proposals."*
4. **Step 4 — Change Impact Simulator (`#/simulations`):**
   - Apply policy constraints: Prohibit 3DES & CBC, require AES-256-GCM, require DH19+, require PFS, enforce IKEv2.
5. **Step 5 — Execute Simulation:**
   - Click **"SIMULATE CHANGE"**. Call invokes real backend `POST /api/v1/simulations`.
6. **Step 6 — Blast Radius Assessment:**
   - Inspect the classification cards:
     - Hardened: Upgrades cleanly.
     - Unchanged: Already compliant.
     - Incompatible: Immediate outage (7 tunnels).
     - Latent Failure: Rekey outage (3 tunnels).
     - Unknown: Incomplete vendor scope (2 tunnels).
   - Show that total tunnels strictly reconcile ($11 + 17 + 7 + 3 + 2 = 40$).
7. **Step 7 — Safe Migration Planner (`#/migration-plans`):**
   - Show sequenced rollout waves (Canary → Low Centrality → Intermediate → Core Hubs).
   - **Critical Invariant:** Point out the **Rollout Blockers** section. Incompatible and Latent Failure tunnels are strictly barred from entering automated waves.
   - Inspect a wave's rollback procedure artifact.
8. **Step 8 — Prediction vs Reality (`#/prediction-vs-reality`):**
   - Present the 5 empirical container lab scenarios.
   - Verify label: *"5/5 controlled testbed scenarios matched"*.
9. **Step 9 — LAB-05 Latent Rekey Drill-Down:**
   - Click scenario **LAB-05**.
   - Show event lifecycle: `CHILD_SA ACTIVE` → `CREATE_CHILD_SA Rekey` → `NO_PROPOSAL_CHOSEN` → `LATENT FAILURE MATCH`.
   - Inspect raw container logs (`charon.log`) and PCAP packet details.
10. **Step 10 — Cryptographic Evidence Chain (`#/evidence`):**
    - Show the 5-link provenance chain:
      `Configuration (E-001) → Negotiation (E-005) → Simulation (E-008) → Lab Log (E-013) → PCAP (E-014)`
    - Click an artifact to prove zero orphan IDs.
11. **Step 11 — Grounded AI Reasoning (`#/ai-reasoning`):**
    - Inspect the grounded explanation for finding `FIND-LATENT-01`.
    - Show the deterministic breakdown: *Observed Facts*, *Derived Facts*, *Unknown Scope*, and *Recommended Action*.
    - Emphasize: Provider is deterministic and evidence-grounded. The AI cannot invent ciphers or alter deterministic severities.
12. **Step 12 — Change-Impact Report (`#/reports/change-impact`):**
    - Present the comprehensive audit report generated for change advisory boards.
    - Click **"Export JSON"** to demonstrate integration readiness.

*Alternatively, click the **"Run Full Demo Flow"** button in the header bar for an automated walkthrough.*

---

## 5. Known Limitations & Constraints

- **Scope Boundary:** No production configuration push is implemented. STATEFLUX is designed strictly as an intelligence, simulation, and migration planning platform to protect production networks from accidental disruption.
- **Air-Gapped Operation:** All CSS, fonts, SVG icons, and JavaScript components are bundled locally. No internet access is required during evaluation.
- **Dataset Mode:** The system operates in `CONTROLLED TESTBED` mode with synthetic fleet configuration models and containerized strongSwan/Libreswan testbed artifacts.

---

## 6. Emergency Troubleshooting

| Symptom | Cause | Resolution |
| :--- | :--- | :--- |
| **Port 8000 already in use** | A previous Python background task is still running. | Run `Get-Process python \| Stop-Process -Force` in PowerShell, then re-run `python run.py`. |
| **Dataset not loaded error** | App was started outside lifespan context in custom scripts. | Always run via `python run.py` or use `with TestClient(app) as client:` in scripts. |
| **Browser displays cached styles** | Browser cached an earlier CSS version. | Press `Ctrl + Shift + R` or `Ctrl + F5` to force hard reload. |

---

**FREEZE VERIFIED BY STATEFLUX QA SUITE (186/186 TESTS PASSING)**
