"""
FastAPI REST API Bridge for SOC UEBA Anomaly Detector
Serves live alerts, simulation injection, step-up verification,
and guardrailed customer dataset analysis for the React Frontend.
"""

import sys
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure backend root is on sys.path
BACKEND_ROOT = Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from src.cert_engine import (
    get_ldap_users,
    get_user_logs,
    get_user_ground_truth,
    get_audit_history,
    verify_otp_step_up,
    log_audit_action,
    ingest_data_v2,
    DB_PATH,
    SCENARIO_DEFINITIONS,
)
from src.baselining import UserBehaviorProfiler
from src.threat_detector import ThreatDetector
from src.prioritizer import rank_incident_queue, INVESTIGATOR_CAPACITY
from src.customer_analysis import analyze_customer_dataset

# ── App Initialization ───────────────────────────────────────────────────────

app = FastAPI(
    title="SOC Anomaly Detector API",
    description="REST backend for the Insider-Threat UEBA Dashboard",
    version="2.0.0",
)

# Enable CORS for the frontend Vite dev server (localhost:5173) and any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    """Auto-ingest the CERT v2 dataset if the DB doesn't exist yet."""
    if not DB_PATH.exists():
        print("⏳ Ingesting data_v2 dataset (2,500 users × 180 days). This may take a moment…")
        ingest_data_v2()
        print("✅ Ingestion complete!")


# Lazily initialized after DB is guaranteed to exist
_profiler: Optional[UserBehaviorProfiler] = None
_detector: Optional[ThreatDetector] = None


def get_profiler() -> UserBehaviorProfiler:
    global _profiler
    if _profiler is None:
        _profiler = UserBehaviorProfiler(DB_PATH)
    return _profiler


def get_detector() -> ThreatDetector:
    global _detector
    if _detector is None:
        _detector = ThreatDetector(db_path=DB_PATH)
    return _detector


# ── Pydantic Models ──────────────────────────────────────────────────────────

class VerificationRequest(BaseModel):
    user_id: str
    otp: str


class AuditPayload(BaseModel):
    user_id: str
    actor: str
    action: str
    status: str
    justification: str
    ai_override: bool = False


# ── Constants ────────────────────────────────────────────────────────────────

NAME_MAP = {
    "EMP101": "Aarav Sharma",
    "EMP205": "Kavya R",
    "EMP302": "Rohan Sen",
    "EMP928": "Zoya Khan",
    "SNN2223": "Siddharth Verma",
    "KHX2969": "Meera Krishnan",
    "UPJ2100": "Naveen Raj",
    "QAK7911": "Aditi Rao",
    "FKX1002": "Farhan Ali",
    "UWY3981": "Tanvi Shah",
    "YWJ6443": "Ethan George",
    "ZXZ4586": "Harini Kumar",
}

STATUS_MAP = {
    "LOW": "APPROVED",
    "MEDIUM": "VERIFYING",
    "HIGH": "FROZEN",
    "CRITICAL": "BLOCKED",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def format_incident(
    user: Dict[str, Any],
    ground_truth: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    uid = user.get("user_id", "")
    level = user.get("risk_level", "LOW")
    score = int(user.get("risk_score", 15))

    # Map status
    raw_status = user.get("status", "")
    if "APPROVED" in raw_status:
        status = "APPROVED"
    elif "VERIF" in raw_status or level == "MEDIUM":
        status = "VERIFYING"
    elif "FROZEN" in raw_status or level == "HIGH":
        status = "FROZEN"
    elif "BLOCK" in raw_status or level == "CRITICAL":
        status = "BLOCKED"
    else:
        status = STATUS_MAP.get(level, "APPROVED")

    name = NAME_MAP.get(uid, f"Operator {uid}")

    city = user.get("home_city") or "HQ"
    country = user.get("home_country") or "US"
    location = f"{city}, {country}" if city != "HQ" else "HQ Office"

    if ground_truth and "description" in ground_truth:
        reason = ground_truth["description"]
    elif ground_truth and ground_truth.get("scenario") in SCENARIO_DEFINITIONS:
        reason = SCENARIO_DEFINITIONS[ground_truth["scenario"]]["title"]
    elif level == "CRITICAL":
        reason = "Privileged data exfiltration & massive external file upload detected"
    elif level == "HIGH":
        reason = "Abnormal sensitive resource access burst & off-hours credential misuse"
    elif level == "MEDIUM":
        reason = "Unusual login location and new device fingerprint"
    else:
        reason = "Activity consistent with established peer behavioral baseline"

    return {
        "user_id": uid,
        "name": name,
        "department": user.get("department", "Engineering"),
        "risk_score": score,
        "level": level,
        "location": location,
        "primary_reason": reason,
        "status": status,
        "last_seen": "just now",
    }


# ═════════════════════════════════════════════════════════════════════════════
# ROUTES — Core Health & Alerts
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/")
def root():
    return {"message": "SOC UEBA Anomaly Detector API is running", "version": "2.0.0"}


@app.get("/api/health")
def health():
    return {"status": "healthy", "service": "soc-ueba-backend"}


@app.get("/api/alerts")
def get_alerts():
    """Returns top prioritized alerts for the SOC incident queue."""
    users = get_ldap_users()
    if not users:
        return {"alerts": []}

    critical_and_high = [u for u in users if u.get("risk_level") in ("CRITICAL", "HIGH")]
    mediums = [u for u in users if u.get("risk_level") == "MEDIUM"]
    lows = [u for u in users if u.get("risk_level") == "LOW"]

    selected = critical_and_high[:10] + mediums[:5] + lows[:5]

    results = []
    for u in selected:
        gt = get_user_ground_truth(u["user_id"])
        results.append(format_incident(u, gt))

    return {"alerts": results}


# ═════════════════════════════════════════════════════════════════════════════
# ROUTES — User Details, Baseline, Drift, Analysis
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/users")
def list_users():
    """Returns all LDAP users."""
    return get_ldap_users()


@app.get("/api/users/{uid}/logs")
def user_logs(uid: str):
    """Returns raw telemetry logs for a user."""
    return get_user_logs(uid)


@app.get("/api/users/{uid}/baseline")
def user_baseline(uid: str):
    """Returns the behavioral baseline profile for a user."""
    return get_profiler().build_user_baseline(uid)


@app.get("/api/users/{uid}/observed")
def user_observed(uid: str):
    """Returns recent observed activity for a user."""
    return get_profiler().get_recent_observed_activity(uid)


@app.get("/api/users/{uid}/drift")
def user_drift(uid: str):
    """Returns longitudinal drift series (risk, egress, off-hours over time)."""
    return get_profiler().get_longitudinal_drift_series(uid)


@app.get("/api/users/{uid}/analyze")
def analyze_user(uid: str):
    """Runs the full Gemini UEBA threat assessment for a user."""
    assessment = get_detector().analyze_user(uid)
    return assessment.model_dump() if assessment else None


@app.get("/api/users/{uid}/stats")
def user_stats(uid: str):
    """Pre-aggregated timeline, hourly distribution, and event counts."""
    logs = get_user_logs(uid)

    stream_names = ["logon", "file", "device"]
    day_counts: Dict[str, Dict[str, int]] = {}
    hours = [0] * 24

    for s in stream_names:
        for rec in logs.get(s, []):
            ts = rec.get("timestamp", rec.get("date", ""))
            try:
                dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
                dl = dt.strftime("%Y-%m-%d")
                if dl not in day_counts:
                    day_counts[dl] = {"logon": 0, "file": 0, "device": 0}
                day_counts[dl][s] += 1
                hours[dt.hour] += 1
            except Exception:
                pass

    return {
        "timeline_events": day_counts,
        "hourly_distribution": hours,
        "total_events": {
            "logon": len(logs.get("logon", [])),
            "file": len(logs.get("file", [])),
            "device": len(logs.get("device", [])),
            "hr": len(logs.get("hr", [])),
            "labels": len(logs.get("labels", [])),
        },
    }


@app.get("/api/queue")
def incident_queue():
    """Returns the ranked SOC investigator queue."""
    users = get_ldap_users()
    detector = get_detector()
    q_items = []
    for u in users:
        assessment = detector.get_cached_assessment(u["user_id"])
        score = assessment.risk_score if assessment else 0
        q_items.append({
            "user_id": u["user_id"],
            "risk_score": score,
            "department": u.get("department", ""),
        })
    return rank_incident_queue(q_items, capacity=INVESTIGATOR_CAPACITY)


# ═════════════════════════════════════════════════════════════════════════════
# ROUTES — Simulation Injection
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/simulation/inject/{scenario_type}")
def inject_simulation(scenario_type: str):
    """
    Injects a live simulation scenario for one-click testing:
    normal -> APPROVED, medium -> VERIFYING, high -> FROZEN, critical -> BLOCKED
    """
    st_lower = scenario_type.lower()

    presets = {
        "normal": {
            "user_id": "EMP101",
            "name": "Aarav Sharma",
            "department": "Engineering",
            "risk_score": 18,
            "level": "LOW",
            "location": "Coimbatore HQ",
            "primary_reason": "Normal workstation access pattern conforming to baseline",
            "status": "APPROVED",
            "last_seen": "just now",
        },
        "medium": {
            "user_id": "EMP205",
            "name": "Kavya R",
            "department": "Finance",
            "risk_score": 54,
            "level": "MEDIUM",
            "location": "Remote VPN, IN",
            "primary_reason": "New device fingerprint + unusual after-hours financial system access",
            "status": "VERIFYING",
            "last_seen": "just now",
        },
        "high": {
            "user_id": "EMP302",
            "name": "Rohan Sen",
            "department": "Operations",
            "risk_score": 82,
            "level": "HIGH",
            "location": "Bengaluru Office",
            "primary_reason": "Abnormal sensitive-resource access burst; concurrent session anomaly",
            "status": "FROZEN",
            "last_seen": "just now",
        },
        "critical": {
            "user_id": "EMP928",
            "name": "Zoya Khan",
            "department": "SOC",
            "risk_score": 97,
            "level": "CRITICAL",
            "location": "Remote VPN, US",
            "primary_reason": "Privileged data exfiltration pattern: high-volume mass download to USB",
            "status": "BLOCKED",
            "last_seen": "just now",
        },
    }

    if st_lower not in presets:
        raise HTTPException(status_code=400, detail=f"Unknown simulation type: {scenario_type}")

    incident = presets[st_lower]

    log_audit_action(
        user_id=incident["user_id"],
        analyst="Simulated Attack Injector",
        action_taken=f"SIMULATION_{st_lower.upper()}",
        previous_status="BASELINE",
        new_status=incident["status"],
        rationale=incident["primary_reason"],
    )

    return {"incident": incident}


# ═════════════════════════════════════════════════════════════════════════════
# ROUTES — Step-Up Verification (OTP)
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/verification/verify")
def verify_otp(request: VerificationRequest):
    """
    Verifies 6-digit OTP code for step-up authentication.
    Demo bypass code: '123456'
    """
    uid = request.user_id
    code = request.otp.strip()

    success, msg = verify_otp_step_up(uid, code)
    if not success and code == "123456":
        success = True
        msg = "Demo verification code accepted."

    if success:
        log_audit_action(
            user_id=uid,
            analyst="Automated Step-Up MFA",
            action_taken="OTP_VERIFIED",
            previous_status="VERIFYING",
            new_status="APPROVED",
            rationale=f"Step-up OTP challenge passed for {uid}",
        )
        return {
            "success": True,
            "verified": True,
            "message": msg,
            "user_id": uid,
            "status": "APPROVED",
            "risk_score": 14,
            "level": "LOW",
        }
    else:
        return {
            "success": False,
            "verified": False,
            "message": msg or "Invalid verification code. Please try again.",
            "user_id": uid,
        }


# ═════════════════════════════════════════════════════════════════════════════
# ROUTES — Audit Trail
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/audit")
def get_audit(user_id: Optional[str] = None, limit: int = 50):
    """Returns immutable SOC audit trail entries."""
    return get_audit_history(user_id=user_id, limit=limit)


@app.post("/api/audit")
def create_audit(payload: AuditPayload):
    """Creates a new audit trail entry."""
    log_audit_action(
        user_id=payload.user_id,
        analyst=payload.actor,
        action_taken=payload.action,
        previous_status=payload.status,
        new_status=payload.status,
        rationale=payload.justification,
    )
    return {"status": "ok"}


# ═════════════════════════════════════════════════════════════════════════════
# ROUTES — Guardrailed Customer Dataset Analysis (Gemini)
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/dataset/analyze")
async def analyze_dataset(file: UploadFile = File(...)):
    """
    Accepts a customer-uploaded CSV/JSON dataset and runs it through
    a strictly guardrailed Gemini model that ONLY responds based on
    the uploaded data — never mixing in existing enterprise logs.
    """
    content = await file.read()
    text_content = content.decode("utf-8")
    report = analyze_customer_dataset(text_content)
    return {"report": report}


# ═════════════════════════════════════════════════════════════════════════════
# Entrypoint
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
