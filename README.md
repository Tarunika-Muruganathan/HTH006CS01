# Explainable Insider-Threat Behavioral Anomaly Detector (HTH-CS-07)

Enterprise insider threat detection platform featuring a Python/Streamlit analytics backend and a modern React/Vite SOC dashboard.

---

## 📁 Repository Structure

```
HTH006CS01/
├── frontend/             # React 18 + Vite + Tailwind CSS SOC Dashboard
│   ├── src/              # React components, views, and styles
│   ├── package.json      # Node.js dependencies
│   ├── vite.config.js    # Vite configuration
│   └── README.md         # Frontend specific setup & demo guide
│
├── backend/              # Python / Streamlit UEBA & Detection Engine
│   ├── app.py            # Streamlit SOC dashboard & detection app
│   ├── src/              # Core algorithms (baselining, cert_engine, threat_detector, prioritizer)
│   ├── insider_threat_data/ # Enterprise dataset v2 (2,500 users, 180 days)
│   ├── tests/            # Test suite
│   ├── requirements.txt  # Python dependencies
│   └── BACKEND_ANALYSIS.md # Backend architecture notes
│
└── README.md             # Project overview and run instructions
```

---

## 🚀 Getting Started

### 1. Frontend Setup (React + Vite)
```bash
cd frontend
npm install
npm run dev
```
Runs at `http://localhost:5173`.

### 2. Backend Setup (Python + Streamlit)
```bash
cd backend
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
# source .venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```
Runs at `http://localhost:8501`.
