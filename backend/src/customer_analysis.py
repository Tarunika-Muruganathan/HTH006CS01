import json
import os
import csv
import io
from typing import Optional


def analyze_customer_dataset(dataset_content: str, api_key: Optional[str] = None) -> str:
    """
    Analyzes a customer dataset with strict guardrails to only respond to the logs
    and ignore any other data.
    If GEMINI_API_KEY is available, calls Gemini model with strict guardrails.
    Otherwise, performs deterministic statistical anomaly evaluation strictly on the input data.
    """
    key = api_key or os.environ.get("GEMINI_API_KEY")

    if key:
        try:
            import re
            
            # --- PII MASKING (Zero-Trust Data Security) ---
            # Mask IPv4 addresses
            sanitized_content = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[MASKED_IP]', dataset_content)
            # Mask email addresses
            sanitized_content = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[MASKED_EMAIL]', sanitized_content)
            
            from google import genai
            client = genai.Client(api_key=key)

            prompt = f"""
You are a strictly guardrailed Cybersecurity Incident Data Analysis AI.
Your task is to analyze the following dataset provided by a customer and generate a comprehensive security and anomaly report.

STRICT GUARDRAILS & INSTRUCTIONS:
1. You MUST ONLY respond based on the data provided in the dataset below.
2. Do NOT hallucinate or incorporate outside knowledge about users, events, or external data sources.
3. The dataset is strictly isolated. Do NOT reference any other users, logs, or existing baseline data.
4. If the dataset does not contain enough information to make a conclusion, state that clearly.
5. Format the output as a detailed, professional Markdown security audit report.

--- CUSTOMER DATASET ---
{sanitized_content[:50000]}
--- END OF CUSTOMER DATASET ---
"""
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            if response and response.text:
                return response.text
        except Exception as e:
            print(f"[!] Gemini analysis note ({type(e).__name__}: {e}). Falling back to deterministic analysis.")

    # Deterministic Isolated Analysis Engine
    return _generate_deterministic_report(dataset_content)


def _generate_deterministic_report(raw_data: str) -> str:
    """
    Strictly isolated offline audit engine analyzing only the provided dataset text.
    Supports JSON or CSV.
    """
    records = []
    data_format = "unknown"

    # Try parsing JSON
    try:
        parsed = json.loads(raw_data)
        if isinstance(parsed, list):
            records = parsed
            data_format = "JSON"
        elif isinstance(parsed, dict):
            records = parsed.get("records") or parsed.get("logs") or parsed.get("events") or [parsed]
            data_format = "JSON"
    except Exception:
        # Try CSV
        try:
            reader = csv.DictReader(io.StringIO(raw_data))
            records = list(reader)
            if records:
                data_format = "CSV"
        except Exception:
            records = []

    total_records = len(records)
    if total_records == 0:
        return f"""# 🛡️ Customer Dataset Security Audit Report
**Status:** Evaluation Inconclusive
**Isolation Scope:** Isolated Customer Context
**Data Integrity:** Empty or Unparseable Dataset

### Findings
- Received payload could not be parsed as valid JSON or CSV telemetry.
- Records Evaluated: 0
- Recommendation: Ensure customer dataset is provided in standard JSON array or CSV format containing user IDs, timestamps, or activity scores.
"""

    # Compute isolated metrics
    high_risk_records = []
    departments = set()
    users = set()
    total_risk = 0
    scores_present = 0

    for idx, r in enumerate(records):
        if not isinstance(r, dict):
            continue
        uid = r.get("user_id") or r.get("userId") or r.get("employee_id") or f"Record-{idx+1}"
        users.add(str(uid))

        dept = r.get("department") or r.get("dept")
        if dept:
            departments.add(str(dept))

        score = r.get("risk_score") or r.get("score")
        if score is not None:
            try:
                score_num = float(score)
                total_risk += score_num
                scores_present += 1
                level = str(r.get("level") or r.get("risk_level") or ("CRITICAL" if score_num >= 90 else "HIGH" if score_num >= 70 else "MEDIUM" if score_num >= 40 else "LOW")).upper()
                if score_num >= 70 or level in ("HIGH", "CRITICAL", "FROZEN", "BLOCKED"):
                    high_risk_records.append({
                        "user_id": uid,
                        "risk_score": score_num,
                        "level": level,
                        "reason": r.get("primary_reason") or r.get("reason") or r.get("event") or "Elevated telemetry indicator",
                        "status": str(r.get("status") or "PENDING_REVIEW").upper()
                    })
            except (ValueError, TypeError):
                pass

    avg_risk = round(total_risk / scores_present, 1) if scores_present > 0 else "N/A"

    high_risk_section = ""
    if high_risk_records:
        high_risk_section = "### ⚠️ High-Risk Incidents Detected in Customer Dataset\n\n"
        high_risk_section += "| User / Identity | Risk Score | Policy Level | Indicator / Reason | Status |\n"
        high_risk_section += "|---|---|---|---|---|\n"
        for hr in high_risk_records[:15]:
            high_risk_section += f"| `{hr['user_id']}` | **{hr['risk_score']}%** | `{hr['level']}` | {hr['reason']} | `{hr['status']}` |\n"
    else:
        high_risk_section = "### ✅ Zero Critical Anomalies Identified\nNo records exceeded the high-risk threshold (score ≥ 70) within the provided batch.\n"

    return f"""# 🛡️ Customer Dataset Security Audit Report
**Analysis Mode:** Strict Isolated Evaluation (Zero External Cross-Contamination)
**Format Detected:** {data_format}
**Total Telemetry Records:** {total_records:,}
**Unique Identities:** {len(users):,}
**Departments Identified:** {', '.join(sorted(departments)) if departments else 'Not specified'}
**Average Observed Risk:** {avg_risk}%

---

{high_risk_section}

### 🔒 Guardrail & Policy Conformance Summary
- **Data Isolation:** All findings are strictly restricted to the customer-uploaded telemetry payload.
- **Cross-Contamination Protection:** Existing enterprise baselines and external organizational data were strictly prevented from influencing this report.
- **Recommended Action:** Escalate any detected High/Critical records to the SOC priority queue and mandate step-up identity verification.
"""
