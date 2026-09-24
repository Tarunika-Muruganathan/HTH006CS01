"""
FastAPI REST API Bridge for SOC UEBA Anomaly Detector
Serves live alerts, simulation injection, and step-up verification for the React Frontend.
"""

import sys
import csv
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, UploadFile, File
from src.customer_analysis import analyze_customer_dataset, analyze_uploaded_dataset
from src.cert_engine import ingest_data_v2, DB_PATH
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="SOC Anomaly Detector API",
    description="REST backend for the Insider-Threat UEBA Dashboard",
    version="1.0.0"
)

# Ensure backend root is on sys.path
BACKEND_ROOT = Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from src.cert_engine import (
    get_ldap_users,
    get_user_ground_truth,
    verify_otp_step_up,
    log_audit_action,
    get_audit_history,
    SCENARIO_DEFINITIONS,
)


@app.on_event("startup")
def startup_event():
    if not DB_PATH.exists():
        print("Ingesting data_v2 dataset. This may take a moment...")
        ingest_data_v2()
        print("Ingestion complete!")

# Enable CORS for the frontend Vite development server (localhost:5173) and any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class VerificationRequest(BaseModel):
    user_id: str
    otp: str

# Human-readable names for realistic display
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

def format_incident(user: Dict[str, Any], ground_truth: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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

    # Name derivation
    name = NAME_MAP.get(uid, f"Operator {uid}")

    # Location derivation
    city = user.get("home_city") or "HQ"
    country = user.get("home_country") or "US"
    location = f"{city}, {country}" if city != "HQ" else "HQ Office"

    # Explanation derivation
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

@app.get("/")
def root():
    return {"message": "SOC UEBA Anomaly Detector API is running", "version": "1.0.0"}

@app.get("/api/health")
def health():
    return {"status": "healthy", "service": "soc-ueba-backend"}

@app.get("/api/alerts")
def get_alerts():
    """Returns top prioritized alerts for the SOC incident queue."""
    users = get_ldap_users()
    if not users:
        return {"alerts": []}
    
    # Sort: high and critical first, then sample of medium and low
    critical_and_high = [u for u in users if u.get("risk_level") in ("CRITICAL", "HIGH")]
    mediums = [u for u in users if u.get("risk_level") == "MEDIUM"]
    lows = [u for u in users if u.get("risk_level") == "LOW"]

    selected = critical_and_high[:10] + mediums[:5] + lows[:5]

    results = []
    for u in selected:
        gt = get_user_ground_truth(u["user_id"])
        results.append(format_incident(u, gt))

    return {"alerts": results}

@app.post("/api/simulation/inject/{scenario_type}")
def inject_simulation(scenario_type: str):
    """
    Injects a live simulation scenario for one-click testing:
    normal -> APPROVED, medium -> VERIFYING (OTP required),
    high -> FROZEN, critical -> BLOCKED
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
    
    # Audit log the simulation
    log_audit_action(
        user_id=incident["user_id"],
        analyst="Simulated Attack Injector",
        action_taken=f"SIMULATION_{st_lower.upper()}",
        previous_status="BASELINE",
        new_status=incident["status"],
        rationale=incident["primary_reason"]
    )

    return {"incident": incident}

@app.post("/api/verification/verify")
def verify_otp(request: VerificationRequest):
    """
    Verifies 6-digit OTP code for step-up authentication.
    Delegates to backend cert_engine.verify_otp_step_up.
    Demo bypass code: '123456'
    """
    uid = request.user_id
    code = request.otp.strip()

    success, msg = verify_otp_step_up(uid, code)
    if not success and code == "123456":
        # Demo bypass
        success = True
        msg = "Demo verification code accepted."

    if success:
        log_audit_action(
            user_id=uid,
            analyst="Automated Step-Up MFA",
            action_taken="OTP_VERIFIED",
            previous_status="VERIFYING",
            new_status="APPROVED",
            rationale=f"Step-up OTP challenge passed for {uid}"
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


@app.post("/api/dataset/analyze")
async def analyze_dataset(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith((".csv", ".json", ".txt")):
        raise HTTPException(status_code=400, detail="Upload a CSV, JSON, or TXT dataset export.")
    content = await file.read()
    try:
        text_content = content.decode("utf-8-sig")
        result = analyze_uploaded_dataset(text_content, file.filename)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, csv.Error) as exc:
        raise HTTPException(status_code=400, detail=f"We could not read this dataset: {exc}") from exc

    # Gemini is optional. Deterministic incident scoring is always returned so the
    # dashboard remains usable without a configured cloud key.
    if os.environ.get("GEMINI_API_KEY"):
        try:
            result["ai_summary"] = analyze_customer_dataset(text_content[:100_000])
        except Exception as exc:
            result["ai_summary_error"] = f"AI narrative unavailable: {exc}"
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
