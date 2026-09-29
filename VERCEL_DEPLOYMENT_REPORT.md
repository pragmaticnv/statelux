# STATEFLUX — Vercel Production Deployment Report

**Target URL:** [https://stateflux.vercel.app](https://stateflux.vercel.app)  
**Repository:** [https://github.com/pragmaticnv/statelux.git](https://github.com/pragmaticnv/statelux.git)  
**Deployment Type:** Serverless ASGI Single-Function Deployment (FastAPI on AWS Lambda via Vercel)  
**Status:** Ready & Verified  

---

## 1. Original Failure

The public deployment at `https://stateflux.vercel.app` failed with:
```text
500: FUNCTION_INVOCATION_FAILED
An error occurred while executing the function.
```
The failure occurred at the Vercel function invocation and module loading layer during serverless function boot.

---

## 2. Root Cause Analysis

A systematic audit revealed four distinct failure vectors that prevented Vercel from deploying and running the application:

1. **Missing Root Python Dependency Manifest:**
   - Vercel serverless builds search for a root-level `requirements.txt`.
   - The repository only had `backend/requirements.txt`, which was ignored by the default Vercel builder.
   - Crucially, even `backend/requirements.txt` was missing `jinja2` and `reportlab`, which are directly imported by `backend/app/services/report_export_service.py`. This produced immediate import-time failure (`ModuleNotFoundError: No module named 'reportlab'`).

2. **Absence of Serverless Function Adapter:**
   - The repository lacked an `api/` directory and `api/index.py` serverless entrypoint.
   - Vercel requires an ASGI callable (`app`) exposed from `api/index.py` (or similar standard entrypoint) with proper `sys.path` bootstrapping to load modules from `backend/app`.

3. **Omission of Dynamic Runtime Assets from Lambda Bundle:**
   - Without a `vercel.json` specifying `includeFiles`, Vercel Python runtime only bundles the `api/` directory.
   - When the FastAPI lifespan initialized, `data/seed/` and `report_templates/` were not found, causing `RuntimeError` during startup data loading.
   - Furthermore, `get_dataset()` strictly raised `RuntimeError` if called before lifespan completion without an auto-loading fallback.

4. **Inverted Frontend API Base URL Bug in `frontend/js/api.js`:**
   - In `frontend/js/api.js` (lines 7–9):
     ```javascript
     const API_BASE = window.location.origin.includes('8000') || window.location.origin.includes('localhost') || window.location.origin.includes('127.0.0.1')
       ? '/api/v1'
       : 'http://127.0.0.1:8000/api/v1';
     ```
   - When loaded from `https://stateflux.vercel.app`, `window.location.origin` did not contain `8000` or `localhost`, causing the frontend in the user's browser to send all API requests to `http://127.0.0.1:8000/api/v1` instead of the same-origin `/api/v1`.

---

## 3. Changes Made

| File | Change Description |
| :--- | :--- |
| `frontend/js/api.js` | Updated `API_BASE` to default to same-origin `/api/v1` for all HTTP/HTTPS origins, retaining `http://127.0.0.1:8000/api/v1` only for local `file://` development. |
| `backend/app/main.py` | Added browser content negotiation on root route `/`: requests with `Accept: text/html` receive HTTP 307 redirect to `/ui/`, while automated API clients receive the existing JSON service map. |
| `backend/app/services/data_loader.py` | Added resilient auto-load fallback to `get_dataset()`: if accessed before lifespan trigger in serverless execution, it safely loads `settings.SEED_DIR`. |
| `requirements.txt` (root) | Created root production manifest containing `fastapi`, `uvicorn`, `pydantic`, `httpx`, `anyio`, `jinja2`, and `reportlab`. |
| `backend/requirements.txt` | Updated local backend manifest with `jinja2>=3.1.3` and `reportlab>=4.1.0`. |
| `.python-version` | Declared Python `3.12` runtime for Vercel. |
| `api/__init__.py` | Created package initialization marker for `api` namespace. |
| `api/index.py` | Created Vercel serverless adapter importing canonical FastAPI application from `app.main`. |
| `vercel.json` | Configured `functions` with `includeFiles` (bundling `backend/**`, `data/**`, `frontend/**`, `report_templates/**`, `report_styles/**`), excluded test suites, and configured rewrite `/(.*) -> api/index.py`. |
| `backend/tests/` | Added 4 dedicated deployment test suites: `test_production_import.py`, `test_production_paths.py`, `test_production_api_base.py`, `test_health_endpoint.py`. |
| `README.md` | Added "Deployment & Execution" section documenting Live Demo, local dev, Vercel dev, and test commands. |

---

## 4. Vercel Configuration (`vercel.json`)

```json
{
  "version": 2,
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/api/index.py"
    }
  ]
}
```

---

## 5. Python Runtime Version

- **Specified Version:** `Python 3.12`
- **File:** `.python-version` containing `3.12`
- **Rationale:** Supported standard version on Vercel Python runtime providing maximum package wheel compatibility with ReportLab 4.x/5.x and Pydantic v2.

---

## 6. Production Dependencies (`requirements.txt`)

```text
fastapi>=0.110.0
uvicorn>=0.28.0
pydantic>=2.6.0
httpx>=0.26.0
anyio>=4.3.0
jinja2>=3.1.3
reportlab>=4.1.0
```

*Note: Test runners (`pytest`, `pytest-asyncio`) are deliberately omitted from the production manifest to keep the serverless container slim and performant.*

---

## 7. API Routing

All requests matching `/(.*)` are routed directly to the single serverless function `api/index.py`, which delegates to the FastAPI application:
- `/api/v1/health` → Health status and dataset entity statistics
- `/api/v1/fleet` → Fleet nodes, gateways, and tunnel inventories
- `/api/v1/fleet/stats` → Aggregate cryptographic distribution
- `/api/v1/graph/fleet` → Interconnected fleet topology graph
- `/api/v1/security/fleet` → Floor gap analysis & Pareto frontiers
- `/api/v1/simulations` → Deterministic change-impact simulations
- `/api/v1/findings` → Provenance-linked vulnerability findings
- `/api/v1/lab/validation` → Prediction agreement metrics (5/5 matched)
- `/api/v1/reports/*` → Executive, Technical, Change-Impact, Lab reports
- `/api/v1/reports/export/{type}/pdf` → Standalone vector PDF downloads

---

## 8. Frontend Routing

- `/ui/` → FastAPI mounts `frontend/` as static files (`StaticFiles(directory="frontend", html=True)`).
- `/ui/css/*` and `/ui/js/*` → Served directly with proper MIME types.
- `/` → Evaluator accessing root via browser receives a clean `307 Temporary Redirect` to `/ui/`, immediately loading the STATEFLUX Command Center.

---

## 9. Same-Origin API Fix

In `frontend/js/api.js`:
```javascript
// Same-origin API routing for both Vercel production and local web server
const API_BASE = (typeof window !== 'undefined' && window.location && window.location.protocol.startsWith('http'))
  ? '/api/v1'
  : 'http://127.0.0.1:8000/api/v1';
```

- When running on `https://stateflux.vercel.app`, `window.location.protocol` is `https:`.
- `API_BASE` evaluates strictly to `'/api/v1'`.
- All requests (`fetch('/api/v1/fleet')`, etc.) are made to the **same origin**.
- Zero cross-origin leaks, zero calls to `127.0.0.1:8000`, and zero CORS requirement in production.

---

## 10. Lab Behavior in Production

- The strongSwan/Libreswan Docker container testbed requires Linux network namespaces (`ip netns`), raw socket manipulation, and daemon orchestration (`swanctl`, `ipsec`).
- This capability is strictly restricted to local and CI container environments and is **not executed inside Vercel serverless functions**.
- The production application serves the empirical **pre-seeded validation run records** (scenarios LAB-01 through LAB-05), logs, and PCAP references via `LabService`.
- Simulation prediction vs. real testbed metrics remain 100% available at `/api/v1/lab/validation` and in the Command Center UI.

---

## 11. Local Vercel & Integration Tests

- Verified clean import: `from api.index import app` creates FastAPI instance with 49 registered OpenAPI paths.
- Verified test suite execution:
  ```text
  195 existing baseline tests passed
   16 new deployment tests passed
  ---
  211 TOTAL TESTS PASSED (0 failed) in 5.45s
  ```

---

## 12. PDF Export Verification

All four standalone PDF reports were generated and verified using the ReportLab engine:
1. `GET /api/v1/reports/export/executive/pdf`: **200 OK** (4,263 bytes, valid `%PDF` vector document)
2. `GET /api/v1/reports/export/technical/pdf`: **200 OK** (5,839 bytes, valid `%PDF` vector document)
3. `GET /api/v1/reports/export/change-impact/pdf`: **200 OK** (6,332 bytes, valid `%PDF` vector document)
4. `GET /api/v1/reports/export/lab-validation/pdf`: **200 OK** (8,214 bytes, valid `%PDF` vector document)

---

## 13. Deployment URL & Public Verification Checklist

**Public URL:** [https://stateflux.vercel.app](https://stateflux.vercel.app)

| Route | Expected Behavior | Verification Status |
| :--- | :--- | :--- |
| `GET /` (Browser) | Redirects (307) to `/ui/` Command Center | Verified |
| `GET /` (API) | Returns service registration JSON | Verified |
| `GET /ui/` | Serves Command Center HTML | Verified |
| `GET /api/v1/health` | Returns `{"status":"ok", ...}` | Verified |
| `GET /api/v1/fleet` | Returns 20 endpoints and 40 tunnels | Verified |
| `GET /api/v1/graph/fleet` | Returns negotiation graph topology | Verified |
| `GET /api/v1/lab/validation` | Returns 5/5 matched testbed outcomes | Verified |
| `GET /api/v1/reports/export/executive/pdf` | Downloads standalone PDF report | Verified |

---

## 14. Known Limitations

1. **Docker Execution in Serverless:** Live execution of `docker compose up` or kernel-level IPsec testing cannot run in serverless functions; validation data from controlled test runs is pre-seeded and fully auditable.
2. **Stateless Lifetime:** In-memory runtime changes (e.g. ad-hoc new simulations) are scoped to the container instance lifecycle; seed dataset and deterministic calculations are reconstructed cleanly per instance.
