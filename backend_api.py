from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, Dict, Any, List
import uvicorn

from src.cert_engine import (
    get_db_connection,
    ingest_data_v2,
    get_ldap_users,
    get_user_logs,
    get_audit_history,
    verify_otp_step_up,
    DB_PATH
)
from src.baselining import UserBehaviorProfiler
from src.gemini_detector import ThreatDetector
from src.prioritizer import rank_incident_queue, INVESTIGATOR_CAPACITY
from src.customer_analysis import analyze_customer_dataset

app = FastAPI(title="Insider Threat Backend")

@app.on_event("startup")
def startup_event():
    if not DB_PATH.exists():
        print("Ingesting data_v2 dataset. This may take a moment...")
        ingest_data_v2()
        print("Ingestion complete!")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

profiler = UserBehaviorProfiler(DB_PATH)
detector = ThreatDetector(db_path=DB_PATH)

@app.get("/users")
def list_users():
    return get_ldap_users()

@app.get("/queue")
def get_queue():
    users = get_ldap_users()
    q_items = []
    for u in users:
        assessment = detector.get_cached_assessment(u["user_id"])
        score = assessment.risk_score if assessment else 0
        q_items.append({"user_id": u["user_id"], "risk_score": score, "department": u["department"]})
    return rank_incident_queue(q_items, capacity=INVESTIGATOR_CAPACITY)

@app.get("/users/{uid}/logs")
def get_logs(uid: str):
    return get_user_logs(uid)

@app.get("/users/{uid}/baseline")
def get_baseline(uid: str):
    return profiler.build_user_baseline(uid)

@app.get("/users/{uid}/drift")
def get_drift(uid: str):
    return profiler.get_longitudinal_drift_series(uid)

@app.get("/users/{uid}/analyze")
def analyze_user_api(uid: str):
    assessment = detector.analyze_user(uid)
    return assessment.model_dump() if assessment else None

@app.get("/users/{uid}/evaluate")
def evaluate_user(uid: str, force: bool = False):
    baseline = profiler.build_user_baseline(uid)
    logs = get_user_logs(uid)
    assessment = detector.evaluate_user(uid, baseline, logs, force_refresh=force)
    return assessment.model_dump() if assessment else None

@app.post("/verify_otp")
def verify_otp(payload: Dict[str, str] = Body(...)):
    uid = payload.get("uid")
    otp_val = payload.get("otp_val")
    ok, msg = verify_otp_step_up(uid, otp_val)
    return {"ok": ok, "msg": msg}

@app.get("/audit")
def get_audit(user_id: Optional[str] = None, limit: int = 50):
    return get_audit_history(user_id=user_id, limit=limit)

@app.post("/analyze_dataset")
async def analyze_dataset(file: UploadFile = File(...)):
    content = await file.read()
    text_content = content.decode("utf-8")
    report = analyze_customer_dataset(text_content)
    return {"report": report}

if __name__ == "__main__":
    uvicorn.run("backend_api:app", host="0.0.0.0", port=8000, reload=True)

@app.get("/users/{uid}/observed")
def get_observed(uid: str):
    return profiler.get_recent_observed_activity(uid)

from pydantic import BaseModel as BM
class AuditPayload(BM):
    user_id: str
    actor: str
    action: str
    status: str
    justification: str
    ai_override: bool = False

from src.cert_engine import log_audit_action
@app.post("/audit")
def create_audit(payload: AuditPayload):
    log_audit_action(payload.user_id, payload.actor, payload.action, payload.status, payload.justification, payload.ai_override)
    return {"status": "ok"}

from datetime import datetime
@app.get("/users/{uid}/stats")
def get_user_stats(uid: str):
    logs = get_user_logs(uid)
    
    stream_names = ["logon", "file", "device"]
    day_counts = {}
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
            "labels": len(logs.get("labels", []))
        }
    }
