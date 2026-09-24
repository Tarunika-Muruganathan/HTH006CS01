import json
import os
import csv
import io
from collections import Counter
from typing import Any, Dict, List

try:
    from google import genai
    from google.genai import types
    _HAS_GENAI = True
except ImportError:
    _HAS_GENAI = False


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
    """Deterministic local score; evaluates location, apps, and files accessed."""
    points, reasons = 0, []
    row_str = " ".join(f"{k} {v}" for k, v in row.items()).lower()
    
    # 1. Direct Risk Score Override (if provided)
    supplied = _field(row, "risk_score", "score", "risk", "severity", "level")
    if supplied not in (None, ""):
        val = str(supplied).strip().upper()
        if val in ["CRITICAL", "HIGH"]: return 95, ["High severity level found in dataset"]
        if val == "MEDIUM": return 65, ["Medium severity level found in dataset"]
        if val == "LOW": return 15, ["Low severity level found in dataset"]
        try:
            return max(0, min(100, int(float(supplied)))), ["Risk score supplied by the uploaded dataset"]
        except (TypeError, ValueError):
            pass

    # Extract specific context fields
    location = str(_field(row, "location", "country", "city", "ip_location", "region")).lower()
    app = str(_field(row, "app", "application", "service", "process", "software")).lower()
    file_acc = str(_field(row, "file", "filename", "resource", "data", "object", "accessed_files")).lower()

    # 2. Location-Based Logic
    risky_locations = ["russia", "china", "north korea", "iran", "unknown", "tor", "vpn", "proxy", "darkweb"]
    if any(loc in location for loc in risky_locations):
        points += 35
        reasons.append(f"Suspicious login location detected ({location.title()})")
    elif "impossible travel" in row_str or "unusual location" in row_str or "new location" in row_str:
        points += 40
        reasons.append("Impossible travel or unusual login location detected")

    # 3. Application Usage Logic
    sensitive_apps = ["vault", "admin", "root", "aws console", "azure", "powershell", "cmd", "terminal", "shadow it", "psexec"]
    if any(a in app for a in sensitive_apps):
        points += 30
        reasons.append(f"Access to sensitive or high-risk application ({app})")
    if "misconfig" in app or "bypass" in app or "exploit" in app:
        points += 45
        reasons.append(f"Exploitation of misconfigured app or security bypass")

    # 4. File / Resource Access Logic
    sensitive_files = ["confidential", "secret", "password", "customer", "financial", "pii", "ssn", "credit", "keys", ".pem"]
    if any(f in file_acc for f in sensitive_files):
        points += 35
        reasons.append(f"Interaction with highly sensitive files ({file_acc})")
    
    file_count = _field(row, "file_count", "download_count", "volume", "count")
    try:
        if int(float(file_count)) > 50:
            points += 40
            reasons.append("Mass file download or data exfiltration volume detected")
    except (TypeError, ValueError):
        pass

    # 5. Generic Action / Behavior Fallback
    if any(w in row_str for w in ["fail", "error", "unauthorized", "denied", "reject", "block"]):
        if not any("unauthorized" in r for r in reasons):
            points += 25; reasons.append("Failed, unauthorized, or blocked action detected")
            
    if any(w in row_str for w in ["upload", "usb", "exfil", "transfer", "mass download"]):
        if not any("download" in r for r in reasons):
            points += 30; reasons.append("Data transfer, external upload, or bulk operation observed")
            
    if any(w in row_str for w in ["malicious", "attack", "exploit", "cve", "misconfigured", "breach", "threat", "anomaly"]):
        if not any("misconfig" in r for r in reasons):
            points += 50; reasons.append("Suspicious, misconfigured, or malicious signature detected")

    if points > 0:
        return min(100, points), reasons
        
    return 0, ["No high-confidence anomaly signal was detected in the uploaded fields"]


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
            "analysis_mode": "deterministic risk scoring",
        },
    }


def analyze_customer_dataset(dataset_content: str, api_key: str = None) -> str:
    """
    Analyzes a customer dataset using the Gemini AI API.
    Only called when GEMINI_API_KEY is set and google-genai is installed.
    """
    if not _HAS_GENAI:
        raise RuntimeError("google-genai package is not installed. Install with: pip install google-genai")

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
