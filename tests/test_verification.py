"""
End-to-End Verification Test Suite
Project Code: HTH-CS-07
Verifies:
1. EMP101 evaluates to ~18% (LOW, ACCESS APPROVED)
2. AAF0535 evaluates to ~54% (MEDIUM, VERIFICATION REQUIRED / OTP)
3. AAM0658 evaluates to ~84% (HIGH, ACCOUNT TEMPORARILY FROZEN)
4. BBS0039 evaluates to ~98% (CRITICAL, SESSION BLOCKED & ACCOUNT LOCKED)
5. Additive factor integrity: sum(factor.points) == risk_score
6. Investigation queue capacity constraints (K = 3)
7. Step-Up OTP Verification workflow
"""

import sys
import os
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.cert_engine import (
    generate_micro_cert, 
    get_ldap_users, 
    verify_otp_step_up, 
    get_audit_history,
    DB_PATH
)
from src.baselining import UserBehaviorProfiler
from src.gemini_detector import GeminiThreatDetector
from src.prioritizer import rank_incident_queue, INVESTIGATOR_CAPACITY

def run_all_verifications():
    print("=" * 70)
    print("🚀 STARTING CERT r4.2 UEBA DETECTOR VERIFICATION SUITE (HTH-CS-07)")
    print("=" * 70)

    # 1. Verify Dataset Generation
    print("\n[Step 1] Verifying CERT r4.2 Micro-Slice Dataset...")
    counts = generate_micro_cert()
    assert counts["ldap"] == 30, f"Expected 30 LDAP users, got {counts['ldap']}"
    assert counts["logon"] > 1000, f"Logon counts too low: {counts['logon']}"
    assert counts["device"] >= 2, f"Device connect/disconnect missing: {counts['device']}"
    assert counts["file"] > 500, f"File logs missing: {counts['file']}"
    assert counts["email"] > 500, f"Email logs missing: {counts['email']}"
    assert counts["http"] > 1000, f"HTTP logs missing: {counts['http']}"
    print(f"✅ Data Engine passed: All 6 CERT CSVs & SQLite tables generated successfully.")

    # 2. Verify Canonical Scenarios and Additive XAI
    print("\n[Step 2] Verifying Canonical Test Scenarios & Additive Factor Consistency...")
    detector = GeminiThreatDetector()
    
    test_cases = [
        ("EMP101", 18, "LOW", "ACCESS APPROVED"),
        ("AAF0535", 54, "MEDIUM", "VERIFICATION REQUIRED"),
        ("AAM0658", 84, "HIGH", "ACCOUNT TEMPORARILY FROZEN"),
        ("BBS0039", 98, "CRITICAL", "SESSION BLOCKED & ACCOUNT LOCKED")
    ]

    for uid, expected_score, expected_level, expected_action in test_cases:
        assessment = detector.analyze_user(uid)
        
        # Verify score range (within tolerance ~4 points)
        assert abs(assessment.risk_score - expected_score) <= 5, \
            f"{uid} score mismatch: expected ~{expected_score}, got {assessment.risk_score}"
            
        assert assessment.risk_level == expected_level, \
            f"{uid} level mismatch: expected {expected_level}, got {assessment.risk_level}"
            
        assert assessment.action_decision == expected_action, \
            f"{uid} action mismatch: expected {expected_action}, got {assessment.action_decision}"
            
        # Verify strict additive consistency
        factor_sum = sum(f.points for f in assessment.factors)
        assert factor_sum == assessment.risk_score, \
            f"{uid} additive violation: sum of factors ({factor_sum}) != risk_score ({assessment.risk_score})"
            
        # Verify plain English explanation and containment
        assert len(assessment.plain_english_explanation) > 20, f"{uid} missing explanation"
        assert len(assessment.recommended_containment_step) > 10, f"{uid} missing containment"
        assert len(assessment.mitre_attack_tactics) >= 1, f"{uid} missing MITRE tactics"

        print(f"  ✅ {uid}: Score={assessment.risk_score}% ({assessment.risk_level}) -> {assessment.action_decision}")
        print(f"     Additive Factors: {' + '.join(str(f.points) for f in assessment.factors)} = {factor_sum} (Exact Match)")
        print(f"     Explanation: {assessment.plain_english_explanation[:90]}...")

    # 3. Verify Capacity-Constrained Queue (K = 3)
    print("\n[Step 3] Verifying Capacity-Constrained Queue Prioritization...")
    all_users = get_ldap_users()
    profiler = UserBehaviorProfiler()
    queue_items = []
    for u in all_users:
        obs = profiler.get_recent_observed_activity(u["user_id"])
        queue_items.append({
            "user_id": u["user_id"],
            "employee_name": u["employee_name"],
            "role": u["role"],
            "department": u["department"],
            "risk_score": u.get("risk_score", 15),
            "risk_level": u.get("risk_level", "LOW"),
            "total_recent_egress_mb": obs.get("total_recent_egress_mb", 0.0),
            "action_decision": u.get("action_decision", "ACCESS APPROVED")
        })

    queue_res = rank_incident_queue(queue_items, capacity=INVESTIGATOR_CAPACITY)
    assert queue_res["capacity_limit"] == 3, "Queue capacity must be 3"
    assert len(queue_res["active_investigation_slots"]) <= 3, "Active slots cannot exceed 3"
    assert len(queue_res["deferred_backlog"]) == len(all_users) - len(queue_res["active_investigation_slots"])
    
    # Verify top users are the severe threats
    active_ids = [item["user_id"] for item in queue_res["active_investigation_slots"]]
    print(f"  Active Slots (K=3): {active_ids}")
    assert "BBS0039" in active_ids, "BBS0039 (Score 98) must be in active slots"
    assert "AAM0658" in active_ids, "AAM0658 (Score 84) must be in active slots"
    
    # Check backlog reasons
    for backlog_item in queue_res["deferred_backlog"][:3]:
        assert backlog_item["deferral_reason"] is not None and len(backlog_item["deferral_reason"]) > 5
    print(f"  ✅ Priority queue correctly enforced K=3 capacity constraint with explicit deferral rationales.")

    # 4. Verify Step-Up OTP Verification
    print("\n[Step 4] Verifying Step-Up OTP Verification Workflow for AAF0535...")
    # Incorrect OTP test
    fail_res, fail_msg = verify_otp_step_up("AAF0535", "999999")
    assert fail_res is False, "Invalid OTP should fail"
    
    # Correct OTP test
    succ_res, succ_msg = verify_otp_step_up("AAF0535", "123456")
    assert succ_res is True, "Valid OTP 123456 should succeed"
    print(f"  ✅ OTP verified: {succ_msg}")
    
    # Verify audit log recorded the event
    audit_trail = get_audit_history(user_id="AAF0535")
    assert len(audit_trail) >= 1, "Audit log must contain OTP verification event"
    print(f"  ✅ Audit log recorded: {audit_trail[0]['action_taken']} by {audit_trail[0]['analyst']}")

    # 5. Verify Longitudinal Drift
    print("\n[Step 5] Verifying Longitudinal Baseline Drift View...")
    drift = profiler.get_longitudinal_drift_series("AAM0658")
    assert len(drift["days"]) == 30, f"Expected 30 days, got {len(drift['days'])}"
    assert "Day 30" in drift["drift_day"], f"Expected Day 30 drift, got {drift['drift_day']}"
    print(f"  ✅ Longitudinal drift tracking verified: AAM0658 drift detected at {drift['drift_day']}")

    print("\n" + "=" * 70)
    print("🎉 ALL VERIFICATION CRITERIA SATISFIED 100%!")
    print("=" * 70)

if __name__ == "__main__":
    run_all_verifications()
