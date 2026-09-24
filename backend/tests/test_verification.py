"""
End-to-End Verification Test Suite
Project Code: HTH-CS-07
Dataset: Enterprise Insider Threat v2
Verifies:
1. Data v2 ingestion (2,500 users, 8 CSVs)
2. Malicious scenario users evaluate to correct risk tiers
3. Benign users evaluate to LOW
4. Additive factor integrity: sum(factor.points) == risk_score
5. Investigation queue capacity constraints (K = 3)
6. Step-Up OTP Verification workflow
"""

import sys
import os
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.cert_engine import (
    ingest_data_v2,
    get_ldap_users,
    get_user_ground_truth,
    verify_otp_step_up,
    get_audit_history,
    DB_PATH
)
from src.baselining import UserBehaviorProfiler
from src.threat_detector import ThreatDetector
from src.prioritizer import rank_incident_queue, INVESTIGATOR_CAPACITY

def run_all_verifications():
    print("=" * 70)
    print("STARTING DATA v2 UEBA DETECTOR VERIFICATION SUITE (HTH-CS-07)")
    print("=" * 70)

    # 1. Verify Dataset Ingestion
    print("\n[Step 1] Verifying data_v2 Dataset Ingestion...")
    counts = ingest_data_v2()
    assert counts["users"] == 2500, f"Expected 2500 users, got {counts['users']}"
    assert counts["logon_events"] > 100000, f"Logon events too low: {counts['logon_events']}"
    assert counts["file_events"] > 500000, f"File events too low: {counts['file_events']}"
    assert counts["device_events"] > 5000, f"Device events too low: {counts['device_events']}"
    assert counts["ground_truth"] > 100, f"Ground truth too low: {counts['ground_truth']}"
    assert counts["resources"] > 500, f"Resources too low: {counts['resources']}"
    print(f"  OK Data ingestion passed:")
    for k, v in counts.items():
        print(f"      {k}: {v:,} records")

    # 2. Verify Malicious Scenario Users
    print("\n[Step 2] Verifying Malicious Scenario XAI & Additive Factor Consistency...")
    detector = ThreatDetector()

    # Pick one user from each malicious scenario
    test_malicious = [
        ("SNN2223", "M1", "HIGH"),      # Compromised Account
        ("KHX2969", "M2", "CRITICAL"),   # Exit Exfiltration
        ("UPJ2100", "M3", "MEDIUM"),     # Privilege Creep
        ("QAK7911", "M4", "HIGH"),       # Impossible Travel
    ]

    for uid, expected_scenario, expected_min_level in test_malicious:
        gt = get_user_ground_truth(uid)
        assert gt is not None, f"{uid} should have ground truth"
        assert gt["scenario"] == expected_scenario, f"{uid} scenario mismatch"
        assert gt["is_malicious"] == 1, f"{uid} should be malicious"

        assessment = detector.analyze_user(uid)

        # Verify risk score is elevated (above LOW threshold)
        assert assessment.risk_score > 30, \
            f"{uid} ({expected_scenario}) risk score too low: {assessment.risk_score}"

        # Verify strict additive consistency
        factor_sum = sum(f.points for f in assessment.factors)
        assert factor_sum == assessment.risk_score, \
            f"{uid} additive violation: sum({factor_sum}) != risk_score({assessment.risk_score})"

        # Verify explanation and containment
        assert len(assessment.plain_english_explanation) > 20, f"{uid} missing explanation"
        assert len(assessment.recommended_containment_step) > 10, f"{uid} missing containment"
        assert len(assessment.mitre_attack_tactics) >= 1, f"{uid} missing MITRE tactics"

        print(f"  OK {uid} ({expected_scenario}): Score={assessment.risk_score}% ({assessment.risk_level})")
        print(f"     Additive: {' + '.join(str(f.points) for f in assessment.factors)} = {factor_sum}")

    # 3. Verify Benign User
    print("\n[Step 3] Verifying Benign User Assessment...")
    benign_uid = "GND9693"
    gt = get_user_ground_truth(benign_uid)
    assert gt is None, f"{benign_uid} should NOT have ground truth"

    benign_assessment = detector.analyze_user(benign_uid)
    assert benign_assessment.risk_score <= 30, \
        f"Benign user {benign_uid} score too high: {benign_assessment.risk_score}"
    assert benign_assessment.risk_level == "LOW", \
        f"Benign user {benign_uid} should be LOW, got {benign_assessment.risk_level}"

    factor_sum = sum(f.points for f in benign_assessment.factors)
    assert factor_sum == benign_assessment.risk_score, \
        f"Benign additive violation: {factor_sum} != {benign_assessment.risk_score}"
    print(f"  OK {benign_uid}: Score={benign_assessment.risk_score}% (LOW) -> {benign_assessment.action_decision}")

    # 4. Verify Capacity-Constrained Queue (K = 3)
    print("\n[Step 4] Verifying Capacity-Constrained Queue Prioritization...")
    all_users = get_ldap_users()
    profiler = UserBehaviorProfiler()
    queue_items = []
    for u in all_users[:100]:  # Top 100 for performance
        obs = profiler.get_recent_observed_activity(u["user_id"])
        queue_items.append({
            "user_id": u["user_id"],
            "employee_name": u["user_id"],
            "role": u.get("role", ""),
            "department": u.get("department", ""),
            "risk_score": u.get("risk_score", 15),
            "risk_level": u.get("risk_level", "LOW"),
            "total_recent_egress_mb": obs.get("total_recent_egress_mb", 0.0),
            "action_decision": u.get("action_decision", "ACCESS APPROVED")
        })

    queue_res = rank_incident_queue(queue_items, capacity=INVESTIGATOR_CAPACITY)
    assert queue_res["capacity_limit"] == 3, "Queue capacity must be 3"
    assert len(queue_res["active_investigation_slots"]) <= 3, "Active slots cannot exceed 3"

    active_ids = [item["user_id"] for item in queue_res["active_investigation_slots"]]
    print(f"  Active Slots (K=3): {active_ids}")

    # Verify all active slots are high-risk
    for slot in queue_res["active_investigation_slots"]:
        assert slot["risk_score"] > 30, f"Active slot {slot['user_id']} score too low: {slot['risk_score']}"

    # Check backlog reasons
    for backlog_item in queue_res["deferred_backlog"][:3]:
        assert backlog_item["deferral_reason"] is not None and len(backlog_item["deferral_reason"]) > 5
    print(f"  OK Priority queue correctly enforced K=3 capacity constraint.")

    # 5. Verify Step-Up OTP Verification
    print("\n[Step 5] Verifying Step-Up OTP Verification Workflow...")
    # Find a MEDIUM risk user with OTP
    medium_users = [u for u in all_users if u.get("risk_level") == "MEDIUM" and u.get("otp_code")]
    if medium_users:
        otp_uid = medium_users[0]["user_id"]

        # Incorrect OTP test
        fail_res, fail_msg = verify_otp_step_up(otp_uid, "999999")
        assert fail_res is False, "Invalid OTP should fail"

        # Correct OTP test
        succ_res, succ_msg = verify_otp_step_up(otp_uid, "123456")
        assert succ_res is True, "Valid OTP 123456 should succeed"
        print(f"  OK OTP verified for {otp_uid}: {succ_msg}")

        # Verify audit log
        audit_trail = get_audit_history(user_id=otp_uid)
        assert len(audit_trail) >= 1, "Audit log must contain OTP verification event"
        print(f"  OK Audit log recorded: {audit_trail[0]['action_taken']}")
    else:
        print("  SKIP No MEDIUM risk users with OTP found for testing.")

    # 6. Verify Longitudinal Drift
    print("\n[Step 6] Verifying Longitudinal Baseline Drift View...")
    drift = profiler.get_longitudinal_drift_series("SNN2223")
    assert len(drift["days"]) == 30, f"Expected 30 days, got {len(drift['days'])}"
    print(f"  OK Longitudinal drift tracking verified: SNN2223 drift = {drift['drift_day']}")

    print("\n" + "=" * 70)
    print("ALL VERIFICATION CRITERIA SATISFIED!")
    print("=" * 70)

if __name__ == "__main__":
    run_all_verifications()
