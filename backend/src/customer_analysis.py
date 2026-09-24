import json
import os
import csv
import io
from collections import Counter
from typing import Any, Dict, List
from google import genai
from google.genai import types


def _tier(score: int) -> tuple[str, str]:
    score = max(0, min(100, score))
    if score <= 30:
        return "LOW", "APPROVED"
    if score <= 70:
        return "MEDIUM", "VERIFYING"
    if score <= 95:
        return "HIGH", "FROZEN"
    return "CRITICAL", "BLOCKED"


def _as_rows(dataset_content: str, filename: str = "") -> List[Dict[str, Any]]:
    """Read common JSON/CSV customer exports without trusting embedded instructions."""
    if filename.lower().endswith(".json") or dataset_content.lstrip().startswith(("[", "{")):
        parsed = json.loads(dataset_content)
        return parsed if isinstance(parsed, list) else parsed.get("records", parsed.get("data", []))
    return list(csv.DictReader(io.StringIO(dataset_content)))


def _field(row: Dict[str, Any], *names: str, default: str = "") -> Any:
    lowered = {str(key).lower().strip(): value for key, value in row.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return value
    return default


def _risk_for_row(row: Dict[str, Any]) -> tuple[int, List[str]]:
    """Deterministic local score; AI enriches the summary but never executes dataset text."""
    supplied = _field(row, "risk_score", "score", "risk")
    if supplied not in (None, ""):
        try:
            return max(0, min(100, int(float(supplied)))), ["Risk score supplied by the uploaded dataset"]
        except (TypeError, ValueError):
            pass

    points, reasons = 0, []
    hour = _field(row, "hour", "login_hour", "event_hour")
    try:
        if int(float(hour)) < 6 or int(float(hour)) > 20:
            points += 20; reasons.append("Activity occurred outside normal working hours")
    except (TypeError, ValueError):
        pass
    if str(_field(row, "new_device", "unknown_device", default="")).lower() in {"1", "true", "yes"}:
        points += 25; reasons.append("New or unrecognised device")
    if str(_field(row, "external_upload", "file_upload", "usb_transfer", default="")).lower() in {"1", "true", "yes"}:
        points += 35; reasons.append("External file transfer or upload observed")
    failed = _field(row, "failed_logins", "login_failures", default=0)
    try:
        if int(float(failed)) >= 3:
            points += 25; reasons.append("Repeated failed authentication attempts")
    except (TypeError, ValueError):
        pass
    return min(100, points), reasons or ["No high-confidence anomaly signal was detected in the uploaded fields"]


def analyze_uploaded_dataset(dataset_content: str, filename: str = "") -> Dict[str, Any]:
    rows = _as_rows(dataset_content, filename)
    if not rows:
        raise ValueError("The uploaded dataset has no readable records.")

    incidents = []
    for index, row in enumerate(rows[:500]):
        if not isinstance(row, dict):
            continue
        score, reasons = _risk_for_row(row)
        level, status = _tier(score)
        user_id = str(_field(row, "user_id", "employee_id", "user", "id", default=f"UPL-{index + 1:03d}"))
        name = str(_field(row, "name", "user_name", "employee_name", default=user_id))
        incidents.append({
            "user_id": user_id,
            "name": name,
            "department": str(_field(row, "department", "dept", default="Uploaded dataset")),
            "risk_score": score,
            "level": level,
            "location": str(_field(row, "location", "city", "source_location", default="Dataset record")),
            "primary_reason": "; ".join(reasons),
            "status": status,
            "last_seen": str(_field(row, "timestamp", "time", "last_seen", default="Uploaded record")),
        })

    distribution = Counter(item["level"] for item in incidents)
    return {
        "incidents": sorted(incidents, key=lambda item: item["risk_score"], reverse=True),
        "summary": {
            "records_analyzed": len(incidents),
            "distribution": dict(distribution),
            "high_risk_records": distribution["HIGH"] + distribution["CRITICAL"],
            "analysis_mode": "deterministic risk scoring with optional Gemini summary",
        },
    }

def analyze_customer_dataset(dataset_content: str, api_key: str = None) -> str:
    """
    Analyzes a customer dataset with strict guardrails to only respond to the logs
    and ignore any other data.
    """
    key = api_key or os.environ.get("GEMINI_API_KEY")
    client = genai.Client(api_key=key)

    prompt = f"""
    You are a strictly guardrailed Data Analysis AI.
    Your task is to analyze the following dataset provided by a customer and generate a comprehensive security and anomaly report.
    
    STRICT GUARDRAILS & INSTRUCTIONS:
    1. You MUST ONLY respond based on the data provided in the dataset below.
    2. Do NOT hallucinate or incorporate outside knowledge about users, events, or external data sources.
    3. The dataset is strictly isolated. Do NOT reference any other users, logs, or existing baseline data.
    4. If the dataset does not contain enough information to make a conclusion, state that clearly.
    5. Format the output as a detailed Markdown report.

    --- CUSTOMER DATASET ---
    {dataset_content}
    --- END OF CUSTOMER DATASET ---
    """
    
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )
    return response.text
