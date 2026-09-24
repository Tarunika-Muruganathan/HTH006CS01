# VectrGuard — Insider-Threat Anomaly Detection Platform

An explainable UEBA (User & Entity Behavior Analytics) dashboard for SOC operations.  
Upload log datasets (single files or ZIP archives with multiple logs), get deterministic risk scores, and investigate anomalies with an AI-powered assistant.

## Quick Start

### Backend
```bash
cd backend
pip install -r requirements.txt
python server.py
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## Features

- **Multi-file ZIP Upload** — Upload a ZIP archive containing multiple CSV/JSON/TXT log files for unified analysis
- **Deterministic Risk Scoring** — Behavioral baselining with anomaly deviation scoring (0–100)
- **Adaptive Access Policy** — Automatic enforcement: APPROVE / VERIFY (OTP) / FREEZE / BLOCK
- **AI Investigation Assistant** — Contextual chat assistant for incident analysis and recommendations
- **Explainability Evidence** — Full scoring methodology breakdown for every flagged identity
- **Step-up Verification** — OTP-based identity verification for medium-risk sessions
- **Live Dashboard** — Real-time risk distribution charts and incident queue

## Tech Stack

- **Frontend:** React + Vite + Tailwind CSS + Framer Motion + Recharts
- **Backend:** Python FastAPI + Pandas
- **AI:** Optional Gemini API integration for enhanced analysis
