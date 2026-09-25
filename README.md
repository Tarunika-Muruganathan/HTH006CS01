# VectrGuard — Explainable Insider-Threat Anomaly Detector

**Hack the Horizon · HTH-CS-07 · THE ALGORITHMISTS**

VectrGuard is a security operations dashboard built with **React and FastAPI**. Analysts can upload customer telemetry, read a security audit report, inspect identity risk and policy states, and ask an assistant about a selected incident.

This README describes the implementation on **`main`**. The backend entry point is [`backend/server.py`](backend/server.py); Streamlit is no longer required.

## Features

- Customer uploads through CSV, JSON, text, Excel, or ZIP files.
- Markdown audit reports from Gemini when configured, with a local statistical fallback.
- A dashboard and identity directory populated from the uploaded data preview.
- Incident details, risk indicators, access status, and contextual assistant responses.
- A separate SQLite-backed demonstration engine with behavioral baselines, 30-day drift, explainable assessments, a three-slot investigation queue, OTP simulation, and audit history.
- IPv4/email masking before customer dataset text is sent to Gemini, and encryption of audit rationales written through the audit helper.

## Tech stack and repository layout

| Layer | Technologies |
|---|---|
| Frontend | React 18, Vite, Tailwind CSS, Framer Motion, Recharts, Axios |
| Reports | React Markdown and remark-gfm |
| Backend | Python, FastAPI, Pydantic, Uvicorn |
| Data | SQLite, pandas, openpyxl |
| AI | Google Gen AI SDK; optional Gemini integration |
| Audit encryption | cryptography / Fernet |

```text
HTH006CS01/
├── backend/
│   ├── server.py                  # FastAPI routes and upload handling
│   ├── requirements.txt
│   ├── src/
│   │   ├── customer_analysis.py   # Customer report generation and fallback
│   │   ├── cert_engine.py         # SQLite ingestion, policy state, OTP, audit
│   │   ├── baselining.py          # User and department behavior profiles
│   │   ├── threat_detector.py     # Structured UEBA assessments
│   │   ├── prioritizer.py         # Capacity-constrained queue
│   │   └── crypto_utils.py        # Audit rationale encryption
│   ├── insider_threat_data/       # Bundled enterprise demonstration CSVs
│   └── tests/test_verification.py # Dataset verification script
├── frontend/
│   ├── src/App.jsx               # Dashboard state and incident investigation
│   ├── src/api.js                # Axios API configuration
│   ├── src/components/           # Upload, assistant, verification, UI
│   ├── src/views/                # Dashboard and identity directory
│   └── package.json
└── README.md
```

## Run locally

Use Python 3.11+ and a current Node.js LTS release with npm. Run the backend and frontend in separate terminals.

```bash
git clone --branch main https://github.com/Tarunika-Muruganathan/HTH006CS01.git
cd HTH006CS01
```

### 1. Start FastAPI

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn server:app --host 127.0.0.1 --port 8000 --reload
```

On Windows PowerShell, activate with `.\.venv\Scripts\Activate.ps1` instead of `source .venv/bin/activate`.

| Service | Local URL |
|---|---|
| API | <http://localhost:8000> |
| Interactive API documentation | <http://localhost:8000/docs> |
| OpenAPI schema | <http://localhost:8000/openapi.json> |
| Health check | <http://localhost:8000/api/health> |

`python server.py` is also supported from `backend/`; its development entry point binds to `0.0.0.0:8000` with reload enabled.

### 2. Start React

From the repository root in a second terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open <http://localhost:5173>. The client defaults to `http://localhost:8000/api`.

To use another backend, put its public URL in `frontend/.env.local`, then restart Vite:

```dotenv
VITE_API_URL=http://localhost:8000/api
```

Include the `/api` suffix. Keep Gemini keys on the server: Vite environment values are included in the browser bundle.

### 3. Upload and investigate

1. Click **Select Dataset** and choose a supported file.
2. The frontend sends it to `POST /api/dataset/analyze` as multipart form data.
3. Open the generated report and inspect identities in the dashboard or directory.
4. Select an incident to inspect its details and use the contextual AI assistant.

The dashboard starts empty. Bundled enterprise data is not automatically ingested on server startup.

## Customer dataset format and outputs

### Supported inputs

| Input | Current handling |
|---|---|
| `.csv` | Header-based telemetry records; use a consistent schema. |
| `.json` | An array of objects is the most compatible form for both reports and the dashboard preview. |
| `.txt` | Read as text; the offline report expects CSV or JSON content. |
| `.xlsx` | Converted to CSV with pandas and openpyxl; the default worksheet is read. |
| `.xls` | Accepted by the UI, but legacy Excel requires an additional reader such as `xlrd`, absent from the current requirements. Prefer `.xlsx`. |
| `.zip` | Recognized CSV/JSON/TXT/Excel members are read in memory and concatenated; declared uncompressed size is limited to 500 MiB. |

Use explicit risk scores and levels for a consistent dashboard preview. Save this example as `customer_logs.csv`:

```csv
user_id,name,department,timestamp,risk_score,level,status,primary_reason
EMP101,Analyst A,Engineering,2026-01-05T10:00:00Z,18,LOW,APPROVED,Activity within expected hours
EMP205,Analyst B,Finance,2026-01-05T22:30:00Z,54,MEDIUM,VERIFYING,Unusual login location
EMP302,Analyst C,Research,2026-01-05T23:00:00Z,84,HIGH,FROZEN,Restricted file access after hours
EMP928,Analyst D,Operations,2026-01-05T23:30:00Z,98,CRITICAL,BLOCKED,Large external data transfer
```

These are illustrative **input scores**, not expected predictions from raw logs. Useful optional fields include `location` and `last_seen`. The backend preview also recognizes aliases including `userId`, `user_name`, `dept`, `score`, `risk_level`, and `reason`.

### Upload API example

```bash
curl -X POST http://localhost:8000/api/dataset/analyze \
  -F "file=@customer_logs.csv"
```

The response is a JSON object containing:

| Field | Meaning |
|---|---|
| `report` | Markdown audit report, rendered in the UI with a copy-to-clipboard action. |
| `users` | Up to 30 preview records normalized for the dashboard. |

The local report summarizes record count, distinct identities, departments, supplied risk scores, and up to 15 elevated-risk records. It does not run the full baseline detector on arbitrary uploaded logs. If usable numeric scores are absent, an absence of flagged records is not evidence that the dataset is safe.

### Dataset isolation and persistence

Customer report generation receives only the current upload text. The upload endpoint does not ingest the file into the enterprise SQLite database or retrain its baselines. A successful new upload replaces the frontend preview; it does not create persistent, selectable dataset history. Refreshing the page clears that preview.

ZIP members are concatenated rather than joined as relational tables. Mixed CSV headers or multiple JSON documents may therefore produce an incomplete offline report or preview. For consistent results, upload one normalized CSV/JSON dataset. The SQLite user, baseline, and queue endpoints are a separate demonstration workflow and do not automatically reflect customer uploads.

## Gemini and audit configuration

| Variable | Purpose |
|---|---|
| `GEMINI_API_KEY` | Optional server-side key for customer reports, incident chat, and UEBA assessments. |
| `AUDIT_ENCRYPTION_KEY` | Optional persistent Fernet key for audit rationales. Otherwise, the backend creates/uses `backend/.audit_encryption.key`. |
| `VITE_API_URL` | Frontend API base URL; defaults to `http://localhost:8000/api`. |

The backend reads process environment variables; it does not automatically load a `.env` file. Set the Gemini key in the same terminal before starting the server:

```bash
export GEMINI_API_KEY="your-server-side-key"
```

PowerShell equivalent: `$env:GEMINI_API_KEY="your-server-side-key"`.

The current model is `gemini-2.5-flash`, specified in the Python code. Without a key, customer reports use the local CSV/JSON summary and chat uses templated incident-context responses. Provider errors also trigger these fallbacks.

Customer analysis masks IPv4 addresses and email addresses before sending at most the first **50,000 characters** of sanitized dataset text to Gemini. Its prompt requests dataset-grounded findings, peer comparisons, feature attribution, and a confidence statement. These are model-generated explanations; the code does not calculate formal SHAP values or calibrated confidence probabilities.

Chat sends the question and frontend-supplied incident context. Current guardrails are prompt-based: responses are not independently validated against stored evidence. Customer-report masking does not also run on chat context, and other identifiers may remain in uploaded content.

Audit helpers encrypt the `rationale` field, not the entire SQLite database. Keep the same encryption key across restarts and backups; keep `backend/.audit_encryption.key` private and out of commits.

## REST API reference

These routes are implemented in `backend/server.py`. Request schemas are available at `/docs`.

| Method | Route | Output / purpose |
|---|---|---|
| GET | `/` | Service name and version. |
| GET | `/api/health` | Backend availability. |
| POST | `/api/dataset/analyze` | Multipart `file`; returns `{report, users}`. |
| POST | `/api/ai/chat` | JSON `message` and optional `incident_context`; returns `{response}`. |
| GET | `/api/alerts` | Selected enterprise identity alerts. |
| GET | `/api/users` | Enterprise users and policy state. |
| GET | `/api/users/{uid}/logs` | User telemetry from SQLite. |
| GET | `/api/users/{uid}/baseline` | Historical behavior profile. |
| GET | `/api/users/{uid}/observed` | Recent observed behavior. |
| GET | `/api/users/{uid}/drift` | Longitudinal drift data. |
| GET | `/api/users/{uid}/analyze` | Structured assessment; may update cached assessment/policy data. |
| GET | `/api/users/{uid}/stats` | Event counts and hourly/daily activity. |
| GET | `/api/queue` | Active investigation slots and deferred backlog. |
| POST | `/api/simulation/inject/{scenario_type}` | Preset incident: `normal`, `medium`, `high`, or `critical`. |
| POST | `/api/verification/verify` | JSON `user_id` and `otp`; demo step-up verification. |
| GET | `/api/audit` | Audit history; optional `user_id` and `limit`. |
| POST | `/api/audit` | `user_id`, `actor`, `action`, `status`, `justification`; optional `ai_override`. |

Enterprise routes need initialized SQLite tables. They are not an API for the transient customer preview. Routes from the original project brief such as `/api/dashboard/stats`, `/api/incidents`, `/api/investigation/capacity`, and `/api/verification/challenge` are not implemented on this branch.

## Enterprise demonstration engine

The bundled dataset contains 2,500 identities and 180 days of synthetic activity. Its CSVs include user profiles, resources, logon/file/device events, HR events, and scenario labels.

Initialize the demonstration database from `backend/`:

```bash
python -m src.cert_engine --ingest
```

This command **clears and reloads existing enterprise data and policy tables** in `backend/insider_threat_data/cert_v2.db`. Use disposable demonstration data. It is not required for customer report uploads.

### Policy tiers

The structured UEBA assessment model uses these ranges:

| Score | Tier | Decision |
|---|---|---|
| 0–30 | LOW | Access approved |
| 31–70 | MEDIUM | Verification required |
| 71–95 | HIGH | Account temporarily frozen |
| 96–100 | CRITICAL | Session blocked and account locked |

Assessment output includes `risk_score`, `risk_level`, `action_decision`, factors with baseline/observed values, a plain-English explanation, MITRE mappings, and a recommended containment step. The engine adjusts factor points to match the resulting score. Its local enterprise fallback uses bundled scenario labels and seeded pseudo-random scoring; it is not an independently validated detector for unseen customer data.

The customer-report fallback uses separate thresholds: it flags scores of 70 or more and infers missing levels at 40/70/90. Supplied preview levels are accepted directly. These paths are not yet unified with the structured assessment policy above.

### Investigation queue

`backend/src/prioritizer.py` sets `INVESTIGATOR_CAPACITY = 3` and uses:

```text
priority_rank = 0.7 × risk_score + 0.3 × normalized_egress_volume_score
```

Output includes `capacity_limit`, `active_occupied`, `available_slots`, `active_investigation_slots`, and `deferred_backlog` with deferral reasons. Capacity is a code constant. The current `/api/queue` route passes cached risk scores but omits egress measurements, so the egress component uses its default value.

### Demo verification and deployment boundary

OTP verification includes a fixed `123456` demonstration bypass. Access states and containment recommendations are application/demo behavior; the repository does not integrate a real identity provider or endpoint enforcement service. The API currently has no authentication layer and uses wildcard CORS, so it should remain a local hackathon/demo application until those controls are replaced for deployment.

## Build and verification

Build the frontend from `frontend/`:

```bash
npm ci
npm run build
npm run preview
```

Run the existing enterprise verification script from `backend/`:

```bash
python tests/test_verification.py
```

The script re-ingests the bundled dataset and modifies demo policy/audit state. It exercises scenario assessments, factor totals, queue capacity, OTP behavior, and drift. Use a disposable database and leave `GEMINI_API_KEY` unset to exercise the local fallback. These scenario checks do not establish detection accuracy on independent customer datasets.

## Troubleshooting

| Symptom | Check |
|---|---|
| Dashboard says API offline | Confirm FastAPI is on port 8000 and `VITE_API_URL` includes `/api`; restart Vite after changing its environment. |
| No identities on first load | Expected: select a customer dataset. Bundled data is not automatically loaded into the UI. |
| Preview appears but no report | A text file may have been parsed locally even if the backend request failed. Check the API connection and server output. |
| SQLite “no such table” on enterprise routes | Initialize the optional demo database with `python -m src.cert_engine --ingest`. |
| Excel import fails | Prefer `.xlsx` and install `backend/requirements.txt`; `.xls` needs another reader engine. |
| ZIP report or preview is incomplete | Normalize the logs into one CSV/JSON file with a consistent schema. |
| Gemini falls back to a local report | Check the server environment, API key/model access, and provider errors in server output. |
