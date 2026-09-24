# Backend Analysis — SOC Monitor Alignment

Branch analyzed: `backend` (Streamlit / SQLite / CERT r4.2 dataset)

## Data Source
- SQLite DB (`cert_data/`) storing user behavioral logs, LDAP profiles, audit actions, and micro-certificates.
- Core engine: `src/cert_engine.py` — user baselining, log retrieval, audit logging, OTP step-up, micro-cert generation.
- Detector: `src/gemini_detector.py` — Gemini Flash-based threat assessment and UEBA scoring.
- Prioritizer: `src/prioritizer.py` — incident queue ranking with investigator capacity limits.

## Key Endpoints / Data Structures
- User logs (`get_user_logs`) — login times, device fingerprints, resource access patterns.
- Baseline profiler (`UserBehaviorProfiler`) — learns normal behavior per identity.
- Incident queue (`rank_incident_queue`) — ranks by risk score and investigator load.
- Audit/history (`get_audit_history`) — track verification and enforcement actions.

## Frontend Alignment (this branch: `frontend`)
- Mock data (`src/data.js`) uses same identity schema: `user_id`, `name`, `department`, `location`, `risk_score`, `level`, `status`, `last_seen`, `primary_reason`.
- Risk levels (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) map directly to backend policy ranges (0–30 / 31–69 / 70–94 / 95–100).
- Verification modal aligns with backend `verify_otp_step_up` and `generate_micro_cert` flow.
- API client points to `localhost:8000/api` for live backend integration; fallback demo data handles offline state.

## Improvements Made
- Sleek minimal dark theme (`#0a0f1a` base, cyan/blue brand, soft glass surfaces).
- Spring-based animations (Apple fluid-motion: interruptible, velocity-aware, critical damping 1.0 / bounce only on momentum).
- Recharts data visualization (bar + pie) for risk distribution and level proportions.
- Proper spacing rhythm, typography hierarchy, and reduced visual noise.
- Product name removed: "CyberShield" → "SOC Monitor".
