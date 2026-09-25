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
import os
import re
import zipfile
import io
import json
import pandas as pd

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


# NOTE: Auto-ingestion of the CERT insider threat dataset is disabled.
# The dashboard starts empty — only user-uploaded datasets are analyzed and displayed.


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


class ChatRequest(BaseModel):
    message: str
    incident_context: Optional[Dict[str, Any]] = None


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
    Accepts a customer-uploaded CSV/JSON or ZIP dataset and runs it through
    a strictly guardrailed Gemini model that ONLY responds based on
    the uploaded data — never mixing in existing enterprise logs.
    Includes security checks to prevent malicious code injection via zip bombs
    or directory traversal.
    """
    content = await file.read()
    
    # Secure ZIP extraction logic
    if file.filename.endswith(".zip"):
        MAX_UNCOMPRESSED_SIZE = 500 * 1024 * 1024  # 500 MB limit against zip bombs
        total_size = 0
        text_content = ""
        
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                for file_info in zf.infolist():
                    # Prevent directory traversal (Zip Slip)
                    if ".." in file_info.filename or file_info.filename.startswith("/"):
                        continue
                    
                    # Prevent Zip Bomb
                    total_size += file_info.file_size
                    if total_size > MAX_UNCOMPRESSED_SIZE:
                        raise HTTPException(status_code=400, detail="Zip file too large (Zip Bomb protection).")
                    
                    # Extract safe text file types
                    if file_info.filename.endswith((".csv", ".json", ".txt")):
                        extracted_bytes = zf.read(file_info)
                        text_content += extracted_bytes.decode("utf-8", errors="replace") + "\n"
                    # Extract and parse Excel files
                    elif file_info.filename.endswith((".xlsx", ".xls")):
                        extracted_bytes = zf.read(file_info)
                        try:
                            df = pd.read_excel(io.BytesIO(extracted_bytes))
                            text_content += df.to_csv(index=False) + "\n"
                        except Exception as e:
                            print(f"[!] Failed to parse Excel inside zip: {e}")
                        
            if not text_content:
                raise HTTPException(status_code=400, detail="No valid CSV/JSON/TXT/XLSX files found in the zip.")
                
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Invalid zip file.")
    elif file.filename.endswith((".xlsx", ".xls")):
        # Raw Excel upload
        try:
            df = pd.read_excel(io.BytesIO(content))
            text_content = df.to_csv(index=False)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid Excel file: {e}")
    else:
        # Standard uncompressed file
        text_content = content.decode("utf-8", errors="replace")

    report = analyze_customer_dataset(text_content)
    
    # Generate a preview of users to populate the frontend dashboard UI
    parsed_users = []
    try:
        content_sample = text_content.strip()
        items = []
        if content_sample.startswith("[") or content_sample.startswith("{"):
            data = json.loads(text_content)
            items = data if isinstance(data, list) else data.get("records", data.get("items", []))
        else:
            df = pd.read_csv(io.StringIO(text_content), nrows=30)
            items = df.to_dict(orient="records")
            
        for idx, item in enumerate(items[:30]):
            parsed_users.append({
                "user_id": str(item.get("user_id", item.get("userId", f"CUST-{idx+101}"))),
                "name": str(item.get("name", item.get("user_name", f"User {idx+101}"))),
                "department": str(item.get("department", item.get("dept", "Enterprise"))),
                "risk_score": int(item.get("risk_score", item.get("score", 45)) or 45),
                "level": str(item.get("level", item.get("risk_level", "MEDIUM")) or "MEDIUM").upper(),
                "location": str(item.get("location", item.get("source_location", "Customer Telemetry"))),
                "primary_reason": str(item.get("primary_reason", item.get("reason", "Customer dataset ingestion event"))),
                "status": str(item.get("status", "VERIFYING") or "VERIFYING").upper(),
                "last_seen": "just now",
            })
    except Exception as e:
        print(f"[!] Failed to parse preview users for frontend: {e}")

    return {"report": report, "users": parsed_users}


# =============================================================================
# ROUTES - AI Chat Assistant
# =============================================================================

def _build_deterministic_response(message: str, ctx: Optional[Dict[str, Any]]) -> str:
    """Generate a smart contextual response based on the incident and question."""
    msg_lower = message.lower().strip()

    if not ctx:
        return (
            "I can provide deeper analysis once you select an incident from the dashboard. "
            "Upload a dataset and click on any flagged identity to begin investigation. "
            "I'll then be able to explain risk scores, recommend actions, and walk you through the evidence."
        )

    uid = ctx.get("user_id", "Unknown")
    name = ctx.get("name", "Unknown")
    dept = ctx.get("department", "Unknown")
    score = ctx.get("risk_score", 0)
    level = ctx.get("level", "LOW")
    status = ctx.get("status", "APPROVED")
    location = ctx.get("location", "Unknown")
    reason = ctx.get("primary_reason", "No specific anomaly recorded.")

    # --- Action recommendations ---
    if any(kw in msg_lower for kw in ["action", "should i", "what do", "recommend", "next step", "respond"]):
        actions = {
            "CRITICAL": (
                f"**Immediate Actions Required for {name} ({uid}):**\n\n"
                f"1. **BLOCK all active sessions** immediately - this is a critical-severity incident (score: {score}/100)\n"
                f"2. **Revoke credentials** and rotate all access tokens associated with {uid}\n"
                f"3. **Isolate the endpoint** at {location} from the network\n"
                f"4. **Preserve forensic evidence** - capture memory dump and disk image before remediation\n"
                f"5. **Escalate to Incident Commander** and notify {dept} department leadership\n"
                f"6. **File a formal incident report** and begin root cause analysis\n\n"
                f"**Key finding:** {reason}"
            ),
            "HIGH": (
                f"**Recommended Actions for {name} ({uid}):**\n\n"
                f"1. **Freeze the current session** - deny sensitive operations until cleared (score: {score}/100)\n"
                f"2. **Initiate out-of-band identity verification** - call the user directly or use physical badge check\n"
                f"3. **Review recent activity logs** for the past 72 hours in {dept}\n"
                f"4. **Check for lateral movement** from {location}\n"
                f"5. **Place on enhanced monitoring** with 15-minute review intervals\n\n"
                f"**Key finding:** {reason}"
            ),
            "MEDIUM": (
                f"**Suggested Actions for {name} ({uid}):**\n\n"
                f"1. **Require step-up verification** - send OTP or password re-authentication (score: {score}/100)\n"
                f"2. **Review the anomaly trigger** - {reason}\n"
                f"3. **Compare against {dept} department peer baseline** to validate deviation\n"
                f"4. **Monitor for escalation** over the next 24 hours\n"
                f"5. If verified, **re-approve access** and update the behavioral baseline\n"
            ),
            "LOW": (
                f"**Status for {name} ({uid}):**\n\n"
                f"No immediate action required. Risk score is {score}/100 (LOW).\n"
                f"Activity is consistent with the established behavioral baseline.\n"
                f"Continue passive monitoring under standard SOC procedures."
            ),
        }
        return actions.get(level, actions["LOW"])

    # --- Risk score explanation ---
    if any(kw in msg_lower for kw in ["risk", "score", "why", "flagged", "explain", "how"]):
        severity_desc = {
            "CRITICAL": "extremely high - immediate threat to organizational security",
            "HIGH": "elevated - active threat indicators requiring urgent attention",
            "MEDIUM": "moderate - behavioral anomalies detected that warrant verification",
            "LOW": "normal - activity within expected parameters",
        }
        return (
            f"**Risk Assessment for {name} ({uid}):**\n\n"
            f"**Score:** {score}/100 ({level})\n"
            f"**Severity:** {severity_desc.get(level, 'unknown')}\n"
            f"**Department:** {dept}\n"
            f"**Location:** {location}\n\n"
            f"**Primary Detection Trigger:**\n{reason}\n\n"
            f"**Scoring Methodology:**\n"
            f"The risk score is computed using deterministic behavioral baselining. "
            f"It measures the deviation magnitude from {name}'s historical activity pattern, "
            f"weighted by resource sensitivity, temporal anomaly factors (off-hours access), "
            f"and peer-group comparison within the {dept} department.\n\n"
            f"**Current Policy:** {status}"
        )

    # --- Status/policy questions ---
    if any(kw in msg_lower for kw in ["status", "policy", "approved", "blocked", "frozen", "verif"]):
        policy_map = {
            "APPROVED": "Access is currently **allowed**. The user is under passive behavioral monitoring.",
            "VERIFYING": "Access is **paused** pending step-up verification (OTP or password re-entry).",
            "FROZEN": "Session is **frozen**. All sensitive operations are temporarily denied.",
            "BLOCKED": "Access is **fully blocked**. The session has been terminated and escalated to SOC.",
        }
        return (
            f"**Policy Status for {name} ({uid}):**\n\n"
            f"**Current Status:** {status}\n"
            f"{policy_map.get(status, 'Unknown policy state.')}\n\n"
            f"**Risk Level:** {level} (Score: {score}/100)\n"
            f"**Trigger:** {reason}"
        )

    # --- General / catch-all ---
    return (
        f"**Incident Summary for {name} ({uid}):**\n\n"
        f"- **Risk Score:** {score}/100 ({level})\n"
        f"- **Status:** {status}\n"
        f"- **Department:** {dept}\n"
        f"- **Location:** {location}\n"
        f"- **Primary Finding:** {reason}\n\n"
        f"You can ask me to:\n"
        f"- *\"What actions should I take?\"* - Get specific response recommendations\n"
        f"- *\"Explain the risk score\"* - Understand the scoring methodology\n"
        f"- *\"What is the current policy?\"* - Review enforcement decisions"
    )


@app.post("/api/ai/chat")
async def ai_chat(request: ChatRequest):
    """
    AI-powered chat assistant for incident investigation.
    Uses Gemini API if GEMINI_API_KEY is available, otherwise falls back
    to intelligent deterministic responses based on incident context.
    """
    message = request.message
    ctx = request.incident_context
    gemini_key = os.environ.get("GEMINI_API_KEY")

    if gemini_key:
        try:
            from google import genai
            client = genai.Client(api_key=gemini_key)

            context_block = ""
            if ctx:
                context_block = f"""
--- INCIDENT CONTEXT ---
User ID: {ctx.get('user_id', 'N/A')}
Name: {ctx.get('name', 'N/A')}
Department: {ctx.get('department', 'N/A')}
Risk Score: {ctx.get('risk_score', 'N/A')}/100
Risk Level: {ctx.get('level', 'N/A')}
Status: {ctx.get('status', 'N/A')}
Location: {ctx.get('location', 'N/A')}
Primary Reason: {ctx.get('primary_reason', 'N/A')}
--- END CONTEXT ---
"""

            prompt = f"""You are a SOC (Security Operations Center) AI analyst assistant for the VectrGuard UEBA platform.
You help security analysts investigate insider threat incidents.

Rules:
1. Only respond based on the incident context provided. Do not hallucinate external data.
2. Be concise, professional, and actionable.
3. Format responses using Markdown (bold, bullet points, etc.).
4. If no incident context is provided, ask the user to select an incident first.

{context_block}

Analyst question: {message}"""

            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            if response and response.text:
                return {"response": response.text}
        except Exception as e:
            print(f"[!] Gemini chat error ({type(e).__name__}: {e}). Using deterministic fallback.")

    # Deterministic fallback
    reply = _build_deterministic_response(message, ctx)
    return {"response": reply}


# =============================================================================
# Entrypoint
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
