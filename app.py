"""
CERT r4.2 Explainable Insider Threat Behavioral Anomaly Detector
Project Code: HTH-CS-07
Standards: CMU CERT Insider Threat Test Dataset Release 4.2
Core AI Model: Gemini Flash
SOC Investigation Dashboard — V2 (Enhanced)
"""

import os
import json
import sqlite3
import datetime
from pathlib import Path
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from src.cert_engine import (
    get_db_connection,
    get_ldap_users,
    get_user_logs,
    log_audit_action,
    get_audit_history,
    verify_otp_step_up,
    generate_micro_cert,
    DB_PATH,
    DATA_DIR,
    CANONICAL_SCENARIOS,
)
from src.baselining import UserBehaviorProfiler
from src.gemini_detector import GeminiThreatDetector, UEBAAssessment
from src.prioritizer import rank_incident_queue, INVESTIGATOR_CAPACITY

# ─── Page Configuration ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="CERT r4.2 Insider Threat Detector | Gemini Flash",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Global CSS — Dark Glassmorphism SOC Theme ────────────────────────────────
st.markdown("""
<style>
/* ── Reset & base ───────────────────────────────────── */
:root {
    --bg-dark: #060a13;
    --bg-card: #0d1420;
    --bg-card-hover: #111b2c;
    --border: #1c2a3f;
    --border-glow: #1f6feb;
    --text-primary: #e6edf3;
    --text-muted: #7d8590;
    --green: #3fb950;
    --yellow: #d29922;
    --orange: #f0883e;
    --red: #f85149;
    --red-bright: #ff7b72;
    --blue: #58a6ff;
    --purple: #bc8cff;
}
.stApp { background: var(--bg-dark); color: var(--text-primary); }
section[data-testid="stSidebar"] > div { background: #080d18; }

/* ── Keyframes ──────────────────────────────────────── */
@keyframes pulse-border {
    0%, 100% { border-color: var(--red); box-shadow: 0 0 8px rgba(248,81,73,.25); }
    50%      { border-color: var(--red-bright); box-shadow: 0 0 18px rgba(248,81,73,.45); }
}
@keyframes scan-line {
    0%   { background-position: 0 -100%; }
    100% { background-position: 0 200%; }
}

/* ── Header ─────────────────────────────────────────── */
.soc-header {
    background: linear-gradient(135deg, #0a1628 0%, #111d30 100%);
    border: 1px solid var(--border);
    border-left: 4px solid var(--border-glow);
    border-radius: 12px;
    padding: 1.1rem 1.6rem;
    margin-bottom: 1.2rem;
    position: relative;
    overflow: hidden;
}
.soc-header::after {
    content: "";
    position: absolute;
    inset: 0;
    background: linear-gradient(180deg, transparent 45%, rgba(31,111,235,.04) 50%, transparent 55%);
    background-size: 100% 200%;
    animation: scan-line 6s linear infinite;
    pointer-events: none;
}
.soc-header h1 { margin:0; font-size:1.55rem; font-weight:700; color:#fff; letter-spacing:.4px; }
.soc-header .sub { color: var(--text-muted); font-size:.82rem; margin-top:.25rem; }

/* ── Metric pill ────────────────────────────────────── */
.m-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: .85rem .6rem;
    text-align: center;
    transition: border-color .2s, box-shadow .2s;
}
.m-card:hover { border-color: var(--border-glow); box-shadow: 0 0 12px rgba(31,111,235,.15); }
.m-val { font-size: 2rem; font-weight: 800; line-height: 1.1; }
.m-lbl { font-size: .68rem; text-transform: uppercase; letter-spacing: 1.2px; color: var(--text-muted); margin-top: .15rem; }

/* ── Risk badges ────────────────────────────────────── */
.badge { display:inline-block; padding:3px 10px; border-radius:6px; font-weight:700; font-size:.75rem; letter-spacing:.5px; }
.badge-low      { background:rgba(63,185,80,.12); color:var(--green);  border:1px solid rgba(63,185,80,.35); }
.badge-medium   { background:rgba(210,153,34,.12); color:var(--yellow); border:1px solid rgba(210,153,34,.35); }
.badge-high     { background:rgba(248,81,73,.12);  color:var(--red);    border:1px solid rgba(248,81,73,.35); }
.badge-critical { background:rgba(248,81,73,.22);  color:var(--red-bright); border:1px solid var(--red); animation: pulse-border 2.2s ease-in-out infinite; }

/* ── Scenario simulation cards ──────────────────────── */
.sim-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: .7rem .9rem .5rem;
    text-align: center;
    transition: transform .15s, border-color .15s;
}
.sim-card:hover { transform: translateY(-2px); border-color: var(--border-glow); }
.sim-label { font-size: .78rem; color: var(--text-muted); margin-top: .2rem; }

/* ── User identity header ──────────────────────────── */
.user-header {
    background: linear-gradient(135deg, var(--bg-card) 0%, #111d30 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1rem;
}

/* ── OTP panel ──────────────────────────────────────── */
.otp-panel {
    background: rgba(210,153,34,.06);
    border: 2px solid var(--yellow);
    border-radius: 10px;
    padding: 1rem 1.2rem;
    margin-bottom: 1.2rem;
}

/* ── Investigation card ─────────────────────────────── */
.inv-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem;
}

/* ── Additive proof strip ──────────────────────────── */
.proof-strip {
    background: #080e1a;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 14px;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: .82rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

/* ── Sidebar user list ──────────────────────────────── */
.usr-row {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: .55rem .7rem;
    margin-bottom: .45rem;
    transition: border-color .15s;
    cursor: pointer;
}
.usr-row:hover { border-color: var(--border-glow); }

/* ── Queue slot ─────────────────────────────────────── */
.q-active {
    background: linear-gradient(90deg, rgba(248,81,73,.08) 0%, var(--bg-card) 100%);
    border-left: 3px solid var(--red);
    border-radius: 6px;
    padding: 8px 10px;
    margin-bottom: 6px;
}
.q-deferred {
    background: var(--bg-card);
    border-left: 3px solid var(--border);
    border-radius: 6px;
    padding: 6px 10px;
    margin-bottom: 5px;
}

/* ── Streamlit overrides ────────────────────────────── */
.stTabs [data-baseweb="tab-list"] { gap: 4px; }
.stTabs [data-baseweb="tab"] { border-radius: 6px 6px 0 0; }
div[data-testid="stDataFrame"] th { background: #0d1420 !important; }
div[data-testid="stTable"] th { background: #0d1420 !important; }
</style>
""", unsafe_allow_html=True)

# ─── Bootstrap Data ───────────────────────────────────────────────────────────
if not DB_PATH.exists():
    with st.spinner("⏳ Generating CERT r4.2 micro-slice dataset …"):
        generate_micro_cert()

@st.cache_resource
def _engines():
    return UserBehaviorProfiler(DB_PATH), GeminiThreatDetector(db_path=DB_PATH)

profiler, detector = _engines()

# ─── Session State ────────────────────────────────────────────────────────────
if "sel" not in st.session_state:
    st.session_state.sel = "BBS0039"
if "analyst" not in st.session_state:
    st.session_state.analyst = "SOC_ANALYST_01"

# ─── Data ─────────────────────────────────────────────────────────────────────
all_users = get_ldap_users()
user_dict = {u["user_id"]: u for u in all_users}

tier_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
for u in all_users:
    tier_counts[u.get("risk_level", "LOW")] += 1

# ╔═══════════════════════════════════════════════════════════════════╗
# ║                        HEADER BAR                                ║
# ╚═══════════════════════════════════════════════════════════════════╝
hdr_left, hdr_right = st.columns([5, 1])
with hdr_left:
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.markdown(f"""
    <div class="soc-header">
        <h1>🛡️ EXPLAINABLE INSIDER-THREAT BEHAVIORAL ANOMALY DETECTOR</h1>
        <div class="sub">
            PROJECT <b>HTH-CS-07</b> &nbsp;·&nbsp; CMU CERT r4.2 &nbsp;·&nbsp; AI Core: <b>Gemini Flash</b>
            &nbsp;·&nbsp; <span style="color:var(--green)">● LIVE</span> {now_str}
        </div>
    </div>
    """, unsafe_allow_html=True)

# ╔═══════════════════════════════════════════════════════════════════╗
# ║                   EXECUTIVE METRICS BANNER                       ║
# ╚═══════════════════════════════════════════════════════════════════╝
cols = st.columns(6)
metrics_data = [
    (len(all_users), "Monitored Users", "var(--blue)"),
    (tier_counts["LOW"], "Low / Approved", "var(--green)"),
    (tier_counts["MEDIUM"], "Medium / Verifying", "var(--yellow)"),
    (tier_counts["HIGH"], "High / Frozen", "var(--red)"),
    (tier_counts["CRITICAL"], "Critical / Blocked", "var(--red-bright)"),
    (INVESTIGATOR_CAPACITY, "Analyst Slots (K)", "var(--purple)"),
]
for col, (val, label, color) in zip(cols, metrics_data):
    col.markdown(f"""
    <div class="m-card">
        <div class="m-val" style="color:{color}">{val}</div>
        <div class="m-lbl">{label}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("")

# ╔═══════════════════════════════════════════════════════════════════╗
# ║               ONE-CLICK DEMO SIMULATION BAR                      ║
# ╚═══════════════════════════════════════════════════════════════════╝
st.markdown("#### ⚡ One-Click Hackathon Demo Scenarios")
scenarios = [
    ("🟢 Normal Baseline", "EMP101",  "~18", "LOW",      "Norman Empson · PC-1001"),
    ("🟡 Flight Risk",     "AAF0535", "~54", "MEDIUM",   "Althea Fleming · PC-2408"),
    ("🟠 USB Exfiltration","AAM0658", "~84", "HIGH",     "Anthony Miller · PC-9923"),
    ("🔴 Disgruntled",     "BBS0039", "~98", "CRITICAL", "Brandon Starks · PC-9436"),
]
sim_cols = st.columns(4)
for col, (label, uid, score, level, desc) in zip(sim_cols, scenarios):
    with col:
        if st.button(label, key=f"sim_{uid}", width="stretch"):
            st.session_state.sel = uid
            st.rerun()
        badge = f"badge-{level.lower()}"
        st.markdown(f"""<div class="sim-card">
            <span class="badge {badge}">{level} {score}%</span>
            <div class="sim-label">{desc}</div>
        </div>""", unsafe_allow_html=True)

st.markdown("---")

# ╔═══════════════════════════════════════════════════════════════════╗
# ║                       SIDEBAR                                    ║
# ╚═══════════════════════════════════════════════════════════════════╝
with st.sidebar:
    tab_dir, tab_queue = st.tabs(["👥 Directory", "📋 Queue (K=3)"])

    # ── Directory ──
    with tab_dir:
        search = st.text_input("🔍 Search", "", placeholder="Name, ID, or role …")
        filtered = [u for u in all_users if search.lower() in f"{u['employee_name']} {u['user_id']} {u['role']}".lower()] if search else all_users
        for u in filtered:
            uid, lvl, sc = u["user_id"], u.get("risk_level", "LOW"), u.get("risk_score", 15)
            badge = f"badge-{lvl.lower()}"
            c1, c2 = st.columns([4, 1])
            with c1:
                st.markdown(f"""<div class="usr-row">
                    <b>{u['employee_name']}</b> <span style="color:var(--text-muted)">({uid})</span><br>
                    <small style="color:var(--text-muted)">{u['role']}</small>
                    &nbsp;<span class="badge {badge}">{lvl} {sc}%</span>
                </div>""", unsafe_allow_html=True)
            with c2:
                if st.button("→", key=f"sb_{uid}"):
                    st.session_state.sel = uid
                    st.rerun()

    # ── Priority Queue ──
    with tab_queue:
        # Build queue
        q_items = []
        for u in all_users:
            obs = profiler.get_recent_observed_activity(u["user_id"])
            q_items.append({
                "user_id": u["user_id"],
                "employee_name": u["employee_name"],
                "role": u["role"],
                "department": u["department"],
                "risk_score": u.get("risk_score", 15),
                "risk_level": u.get("risk_level", "LOW"),
                "total_recent_egress_mb": obs.get("total_recent_egress_mb", 0.0),
                "action_decision": u.get("action_decision", "ACCESS APPROVED"),
            })
        queue = rank_incident_queue(q_items, capacity=INVESTIGATOR_CAPACITY)

        # Active
        st.markdown(f"**Active Workbenches** — {queue['active_occupied']}/{queue['capacity_limit']}")
        for a in queue["active_investigation_slots"]:
            st.markdown(f"""<div class="q-active">
                <b>{a['slot_assignment']}</b><br>
                {a['employee_name']} ({a['user_id']})
                &nbsp;<span class="badge badge-{a['risk_level'].lower()}">{a['risk_level']} {a['risk_score']}%</span><br>
                <small style="color:var(--text-muted)">Priority: {a['priority_rank']}</small>
            </div>""", unsafe_allow_html=True)
            if st.button(f"Triage {a['user_id']}", key=f"qt_{a['user_id']}"):
                st.session_state.sel = a['user_id']
                st.rerun()

        # Deferred
        st.markdown("**Deferred Backlog**")
        for d in queue["deferred_backlog"][:6]:
            st.markdown(f"""<div class="q-deferred">
                <small><b>{d['user_id']}</b> — {d['employee_name']}<br>
                <span style="color:var(--text-muted)">{d['deferral_reason']}</span></small>
            </div>""", unsafe_allow_html=True)

# ╔═══════════════════════════════════════════════════════════════════╗
# ║                ACTIVE INVESTIGATION WORKBENCH                    ║
# ╚═══════════════════════════════════════════════════════════════════╝
uid = st.session_state.sel
info = user_dict.get(uid, {})
if not info:
    st.error("User not found."); st.stop()

assessment = detector.analyze_user(uid)
baseline   = profiler.build_user_baseline(uid)
observed   = profiler.get_recent_observed_activity(uid)
drift      = profiler.get_longitudinal_drift_series(uid)

# ── User Identity Header ──────────────────────────────────────────────────────
lvl = assessment.risk_level
badge_cls = f"badge-{lvl.lower()}"
color_map = {"LOW": "var(--green)", "MEDIUM": "var(--yellow)", "HIGH": "var(--red)", "CRITICAL": "var(--red-bright)"}
sc_color = color_map.get(lvl, "var(--blue)")

st.markdown(f"""
<div class="user-header">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:.8rem">
        <div>
            <h2 style="margin:0; color:#fff; font-size:1.4rem">{info.get('employee_name',uid)}
                <span style="color:var(--text-muted); font-size:.95rem">({uid})</span>
            </h2>
            <div style="color:var(--text-muted); font-size:.85rem; margin-top:3px">
                {info.get('role')} &nbsp;·&nbsp; {info.get('department')}
                &nbsp;·&nbsp; <code>{baseline.get('primary_pc')}</code>
                &nbsp;·&nbsp; Supervisor: {info.get('supervisor','-')}
            </div>
        </div>
        <div style="text-align:right">
            <div style="font-size:2.2rem; font-weight:800; color:{sc_color}; line-height:1">{assessment.risk_score}<small style="font-size:1rem">%</small></div>
            <span class="badge {badge_cls}" style="font-size:.85rem; padding:4px 12px">{lvl}</span><br>
            <div style="margin-top:4px; font-size:.8rem; font-weight:700; color:var(--blue)">{assessment.action_decision}</div>
        </div>
    </div>
</div>""", unsafe_allow_html=True)

# ── Step-Up OTP for MEDIUM ────────────────────────────────────────────────────
if assessment.risk_level == "MEDIUM":
    st.markdown("""<div class="otp-panel">
        <h4 style="margin:0 0 .4rem; color:var(--yellow)">⚠️ STEP-UP AUTHENTICATION — 6-Digit OTP Required</h4>
        <p style="margin:0; font-size:.85rem; color:var(--text-primary)">
            Flight-risk behavioural anomalies detected. Session held in <b>VERIFYING</b> status pending multi-factor challenge.
        </p>
    </div>""", unsafe_allow_html=True)

    oc1, oc2, oc3 = st.columns([2, 1, 2])
    with oc1:
        otp_val = st.text_input("Enter 6-digit code", max_chars=6, placeholder="123456")
    with oc2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("✓ Verify", type="primary", width="stretch"):
            if otp_val:
                ok, msg = verify_otp_step_up(uid, otp_val)
                if ok:
                    st.success(f"✅ {msg}")
                    st.rerun()
                else:
                    st.error(f"❌ {msg}")
    with oc3:
        st.markdown("<br>", unsafe_allow_html=True)
        st.info("💡 **Demo code:** `123456`")

# ╔═══════════════════════════════════════════════════════════════════╗
# ║                      WORKBENCH TABS                              ║
# ╚═══════════════════════════════════════════════════════════════════╝
tab_xai, tab_drift, tab_timeline, tab_audit, tab_raw = st.tabs([
    "🔍 XAI Investigation",
    "📈 30-Day Baseline Drift",
    "🕐 Activity Timeline",
    "📜 Audit Trail",
    "📂 Raw CERT Telemetry",
])

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — XAI INVESTIGATION
# ═══════════════════════════════════════════════════════════════════════════════
with tab_xai:
    g_col, w_col = st.columns([1, 2])

    # ── Risk Gauge ──
    with g_col:
        gauge_colors = {"LOW": "#3fb950", "MEDIUM": "#d29922", "HIGH": "#f85149", "CRITICAL": "#da3633"}
        gc = gauge_colors.get(lvl, "#58a6ff")

        fig_g = go.Figure(go.Indicator(
            mode="gauge+number",
            value=assessment.risk_score,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": f"<b>{lvl}</b>", "font": {"size": 18, "color": "#ffffff"}},
            number={"font": {"size": 52, "color": gc}, "suffix": "%"},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#3d4f67", "tickwidth": 1},
                "bar":  {"color": gc, "thickness": 0.25},
                "bgcolor": "#0d1420",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 30],  "color": "rgba(63,185,80,.08)"},
                    {"range": [30, 70], "color": "rgba(210,153,34,.08)"},
                    {"range": [70, 95], "color": "rgba(248,81,73,.08)"},
                    {"range": [95, 100],"color": "rgba(218,54,51,.18)"},
                ],
                "threshold": {"line": {"color": "#ffffff", "width": 2}, "thickness": 0.75, "value": assessment.risk_score},
            },
        ))
        fig_g.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=15, r=15, t=45, b=15), height=260)
        st.plotly_chart(fig_g, width="stretch")

        st.markdown(f"**Scenario:** `{assessment.threat_scenario}`")
        st.markdown("**MITRE ATT&CK:**")
        for t in assessment.mitre_attack_tactics:
            st.markdown(f"- 🎯 `{t}`")

    # ── Waterfall Chart ──
    with w_col:
        st.markdown("#### Factor Attribution Waterfall")
        names  = [f.factor_name for f in assessment.factors]
        points = [f.points      for f in assessment.factors]
        colors = ["#f85149" if p > 18 else ("#d29922" if p > 8 else "#3fb950") for p in points]

        fig_w = go.Figure(go.Bar(
            y=names, x=points, orientation="h",
            marker=dict(color=colors, line=dict(width=0)),
            text=[f"+{p}" for p in points],
            textposition="auto",
            textfont=dict(size=13, color="#ffffff"),
        ))
        fig_w.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e6edf3", size=12),
            xaxis=dict(title="Points (additive)", gridcolor="#1c2a3f", zeroline=False),
            yaxis=dict(autorange="reversed"),
            margin=dict(l=10, r=10, t=10, b=10),
            height=260, bargap=0.35,
        )
        st.plotly_chart(fig_w, width="stretch")

        # Additive proof
        s = sum(points)
        eq = " + ".join(str(p) for p in points)
        ok = s == assessment.risk_score
        st.markdown(f"""<div class="proof-strip">
            <span>{eq} = <b>{s}</b></span>
            <span style="color:{'var(--green)' if ok else 'var(--red)'}">{'✅ Additive Consistency Verified' if ok else '❌ Discrepancy'}</span>
        </div>""", unsafe_allow_html=True)

    st.markdown("")

    # ── Explanation + Containment side-by-side ──
    ex1, ex2 = st.columns(2)
    with ex1:
        st.markdown('<div class="inv-card">', unsafe_allow_html=True)
        st.markdown("#### 🧠 Gemini Flash Reasoning")
        st.markdown(assessment.plain_english_explanation)
        st.markdown("</div>", unsafe_allow_html=True)
    with ex2:
        st.markdown('<div class="inv-card">', unsafe_allow_html=True)
        st.markdown("#### 🚨 Containment Recommendation")
        st.markdown(assessment.recommended_containment_step)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("")

    # ── Baseline vs Observed comparison ──
    st.markdown("#### ⚖️ Baseline vs. Observed Comparison")
    rows = []
    for f in assessment.factors:
        rows.append({
            "Factor": f.factor_name,
            "Points": f"+{f.points}",
            "30-Day Baseline": f.baseline_value,
            "Observed (Anomalous)": f.observed_value,
        })
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

    # ── Analyst Remediation ──
    st.markdown("#### 👨‍💻 SOC Analyst Actions")
    a1, a2, a3 = st.columns(3)
    analyst_id = st.session_state.analyst
    with a1:
        if st.button("✅ Approve Access", width="stretch"):
            log_audit_action(uid, analyst_id, "ANALYST_OVERRIDE_APPROVED", info.get("status", ""), "ACCESS APPROVED",
                             "Analyst verified legitimate business rationale.")
            st.toast("✅ Access approved & logged.", icon="✅")
            st.rerun()
    with a2:
        if st.button("⏸️ Maintain Freeze", width="stretch"):
            log_audit_action(uid, analyst_id, "ACCOUNT TEMPORARILY FROZEN", info.get("status", ""), "ACCOUNT TEMPORARILY FROZEN",
                             "Freeze maintained pending forensic extraction.")
            st.toast("⏸️ Freeze maintained & logged.", icon="⏸️")
            st.rerun()
    with a3:
        if st.button("⛔ Terminate & Lock", width="stretch", type="primary"):
            log_audit_action(uid, analyst_id, "SESSION BLOCKED & ACCOUNT LOCKED", info.get("status", ""), "SESSION BLOCKED & ACCOUNT LOCKED",
                             "Emergency revocation: TCP kill, AD lock, badge revocation.")
            st.toast("⛔ Account locked & session terminated!", icon="🔒")
            st.rerun()
    st.caption(f"Actions logged as **{analyst_id}** → immutable `audit_logs` table")

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — 30-DAY BASELINE DRIFT
# ═══════════════════════════════════════════════════════════════════════════════
with tab_drift:
    st.markdown("### 📈 Longitudinal Baseline Drift — 30-Day Trajectory")
    if drift["drift_day"] != "None (Benign Stable Baseline)":
        st.warning(f"🚨 **Threat inception detected:** Behaviour deviated sharply on **{drift['drift_day']}**")
    else:
        st.success("🟢 **Stable baseline** — No anomalous deviation observed.")

    fig_d = go.Figure()
    fig_d.add_trace(go.Scatter(
        x=drift["days"], y=drift["risk_scores"],
        mode="lines+markers", name="Risk Score",
        line=dict(color="#ff7b72", width=3), marker=dict(size=5),
    ))
    fig_d.add_trace(go.Scatter(
        x=drift["days"], y=drift["egress_volumes_mb"],
        mode="lines+markers", name="Egress (MB)",
        line=dict(color="#388bfd", width=2, dash="dot"), yaxis="y2",
    ))
    fig_d.add_trace(go.Scatter(
        x=drift["days"], y=drift["off_hours_events"],
        mode="lines+markers", name="Off-Hours Events",
        line=dict(color="#e3b341", width=2, dash="dash"), yaxis="y3",
    ))

    # Add risk zone bands
    for lo, hi, clr, nm in [(0,30,"rgba(63,185,80,.06)","Safe"), (30,70,"rgba(210,153,34,.06)","Medium"),
                             (70,95,"rgba(248,81,73,.06)","High"), (95,105,"rgba(218,54,51,.1)","Critical")]:
        fig_d.add_hrect(y0=lo, y1=hi, fillcolor=clr, line_width=0, layer="below")

    fig_d.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf3"),
        xaxis=dict(title="Observation Window", gridcolor="#1c2a3f"),
        yaxis=dict(title=dict(text="Risk Score", font=dict(color="#ff7b72")), tickfont=dict(color="#ff7b72"), range=[0, 105], gridcolor="#1c2a3f"),
        yaxis2=dict(title=dict(text="Egress (MB)", font=dict(color="#388bfd")), tickfont=dict(color="#388bfd"), overlaying="y", side="right"),
        yaxis3=dict(title=dict(text="Off-Hours", font=dict(color="#e3b341")), tickfont=dict(color="#e3b341"), anchor="free", overlaying="y", side="right", position=0.95),
        legend=dict(x=0.01, y=0.98, bgcolor="rgba(13,20,32,.85)", bordercolor="#1c2a3f", borderwidth=1),
        margin=dict(l=15, r=40, t=15, b=15), height=420,
    )
    st.plotly_chart(fig_d, width="stretch")

    # Summary stats row
    dc1, dc2, dc3, dc4 = st.columns(4)
    dc1.metric("Peak Risk Score", f"{max(drift['risk_scores'])}%")
    dc2.metric("Peak Egress", f"{max(drift['egress_volumes_mb']):.1f} MB")
    dc3.metric("Total Off-Hours Events", str(sum(drift['off_hours_events'])))
    dc4.metric("Drift Day", drift["drift_day"].split("(")[-1].rstrip(")") if "(" in drift["drift_day"] else "—")

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — ACTIVITY TIMELINE (NEW)
# ═══════════════════════════════════════════════════════════════════════════════
with tab_timeline:
    st.markdown(f"### 🕐 Event Activity Timeline — {uid}")
    st.markdown("Visual breakdown of activity intensity across CERT telemetry streams.")

    logs = get_user_logs(uid)
    # Build a heatmap-style summary: stream × day
    stream_names = ["logon", "file", "email", "http", "device"]
    stream_labels = ["🔑 Logon", "📄 File", "✉️ Email", "🌐 HTTP", "💾 USB"]

    # Build sort key from full dates so we avoid year-less strptime (Python 3.14 deprecation)
    day_labels_set: set[str] = set()
    _label_to_date: dict[str, datetime.datetime] = {}
    for s in stream_names:
        for rec in logs.get(s, []):
            try:
                dt = datetime.datetime.strptime(rec["date"], "%m/%d/%Y %H:%M:%S")
                lbl = dt.strftime("%b %d")
                day_labels_set.add(lbl)
                _label_to_date.setdefault(lbl, dt)
            except Exception:
                pass

    day_labels = sorted(day_labels_set, key=lambda x: _label_to_date.get(x, datetime.datetime.min))
    if not day_labels:
        day_labels = ["No Data"]

    z_matrix = []
    for s in stream_names:
        day_counts = {d: 0 for d in day_labels}
        for rec in logs.get(s, []):
            try:
                dt = datetime.datetime.strptime(rec["date"], "%m/%d/%Y %H:%M:%S")
                dl = dt.strftime("%b %d")
                if dl in day_counts:
                    day_counts[dl] += 1
            except Exception:
                pass
        z_matrix.append([day_counts.get(d, 0) for d in day_labels])

    fig_heat = go.Figure(go.Heatmap(
        z=z_matrix, x=day_labels, y=stream_labels,
        colorscale=[[0, "#0d1420"], [0.3, "#1c3a5e"], [0.6, "#2563a8"], [1.0, "#58a6ff"]],
        showscale=True, colorbar=dict(title=dict(text="Events", font=dict(color="#8b949e")), tickfont=dict(color="#8b949e")),
        hovertemplate="<b>%{y}</b> on %{x}<br>Events: %{z}<extra></extra>",
    ))
    fig_heat.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf3"),
        xaxis=dict(title="Day", gridcolor="#1c2a3f"),
        yaxis=dict(autorange="reversed"),
        margin=dict(l=10, r=10, t=10, b=10), height=250,
    )
    st.plotly_chart(fig_heat, width="stretch")

    # Per-stream event counts
    st.markdown("#### Event Stream Summary")
    sc = st.columns(5)
    for i, (s, lbl) in enumerate(zip(stream_names, stream_labels)):
        cnt = len(logs.get(s, []))
        sc[i].metric(lbl, cnt)

    # Hour-of-day distribution
    st.markdown("#### ⏰ Hour-of-Day Activity Distribution")
    hours = [0] * 24
    for s in stream_names:
        for rec in logs.get(s, []):
            try:
                dt = datetime.datetime.strptime(rec["date"], "%m/%d/%Y %H:%M:%S")
                hours[dt.hour] += 1
            except Exception:
                pass

    fig_hours = go.Figure(go.Bar(
        x=list(range(24)), y=hours,
        marker=dict(
            color=["#f85149" if (h < 7 or h >= 20) else "#3fb950" for h in range(24)],
            line=dict(width=0),
        ),
        hovertemplate="Hour %{x}:00<br>Events: %{y}<extra></extra>",
    ))
    fig_hours.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf3"),
        xaxis=dict(title="Hour of Day (24h)", dtick=1, gridcolor="#1c2a3f"),
        yaxis=dict(title="Total Events", gridcolor="#1c2a3f"),
        margin=dict(l=10, r=10, t=10, b=10), height=240, bargap=0.15,
    )
    # Add off-hours shading
    fig_hours.add_vrect(x0=-0.5, x1=6.5, fillcolor="rgba(248,81,73,.06)", line_width=0, annotation_text="Off-Hours", annotation_position="top left", annotation_font_color="#f85149")
    fig_hours.add_vrect(x0=19.5, x1=23.5, fillcolor="rgba(248,81,73,.06)", line_width=0, annotation_text="Off-Hours", annotation_position="top right", annotation_font_color="#f85149")
    st.plotly_chart(fig_hours, width="stretch")

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4 — AUDIT TRAIL
# ═══════════════════════════════════════════════════════════════════════════════
with tab_audit:
    st.markdown("### 📜 Immutable SOC Audit Trail")
    audit_all, audit_user = st.tabs(["All Events", f"Events for {uid}"])
    with audit_all:
        recs = get_audit_history(limit=50)
        if recs:
            st.dataframe(pd.DataFrame(recs), width="stretch", hide_index=True)
        else:
            st.info("No audit entries yet. Take an analyst action to create one.")
    with audit_user:
        recs = get_audit_history(user_id=uid, limit=30)
        if recs:
            st.dataframe(pd.DataFrame(recs), width="stretch", hide_index=True)
        else:
            st.info(f"No audit entries for {uid}.")

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5 — RAW CERT TELEMETRY
# ═══════════════════════════════════════════════════════════════════════════════
with tab_raw:
    st.markdown(f"### 📂 Raw CERT r4.2 Telemetry — {uid}")
    u_logs = get_user_logs(uid)
    sub_tabs = st.tabs(["🔑 logon", "💾 device", "📄 file", "✉️ email", "🌐 http"])
    table_names = ["logon", "device", "file", "email", "http"]
    for sub, name in zip(sub_tabs, table_names):
        with sub:
            data = u_logs.get(name, [])
            st.caption(f"{len(data)} records")
            if data:
                st.dataframe(pd.DataFrame(data), width="stretch", hide_index=True)
            else:
                st.info(f"No {name} records (complies with baseline).")
