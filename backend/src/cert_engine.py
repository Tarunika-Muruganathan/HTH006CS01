"""
CERT v2 Native Ingestion & Data Engine
Project Code: HTH-CS-07
Standards: Insider Threat Detection — Synthetic Enterprise Dataset v2
"""

import os
import sys
import csv
import sqlite3
import random
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# Project root directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "insider_threat_data"
DB_PATH = PROJECT_ROOT / "insider_threat_data" / "cert_v2.db"

# Schema specification for data_v2 CSV format
CERT_V2_COLUMNS = {
    "users": ["user_id", "role", "department", "peer_group", "work_start", "work_end",
              "home_country", "home_city", "on_call", "primary_device"],
    "logon_events": ["timestamp", "user_id", "device_id", "ip", "country", "city", "action"],
    "file_events": ["timestamp", "user_id", "file_id", "action", "bytes"],
    "device_events": ["timestamp", "user_id", "event"],
    "hr_events": ["user_id", "event", "date"],
    "ground_truth": ["scenario_id", "user_id", "scenario", "is_malicious", "start_date", "end_date", "description"],
    "resources": ["file_id", "owning_department", "sensitivity"],
    "labels_user_day": ["user_id", "date", "scenario", "is_malicious"],
}

# Scenario descriptions mapped from ground_truth scenario codes
SCENARIO_DEFINITIONS = {
    "M1": {
        "name": "Compromised Account",
        "description": "New country + off-hours + sensitive files (subtle variant: new country, normal hours, 8-15 files)",
        "threat_level": "HIGH",
    },
    "M2": {
        "name": "Exit Exfiltration",
        "description": "Escalating downloads of own-dept Confidential/Restricted + USB + external upload; resignation notice for ~2/3",
        "threat_level": "CRITICAL",
    },
    "M3": {
        "name": "Privilege Creep",
        "description": "Low-and-slow drift into another department over 30-45 days, rising sensitivity",
        "threat_level": "MEDIUM",
    },
    "M4": {
        "name": "Impossible Travel",
        "description": "Concurrent overlapping sessions from two distant countries",
        "threat_level": "HIGH",
    },
    "M5": {
        "name": "Data Staging via Email",
        "description": "Many email_attachment events on Confidential/Restricted files over 3-5 days",
        "threat_level": "HIGH",
    },
    "M6": {
        "name": "Sabotage",
        "description": "Burst of deletes on own-dept files, partly off-hours, then back to normal",
        "threat_level": "CRITICAL",
    },
    "M7": {
        "name": "Credential Sharing",
        "description": "A second device active in the same country with overlapping sessions over several weeks",
        "threat_level": "MEDIUM",
    },
}

# Decoy (benign) scenario names — these are NOT malicious
DECOY_SCENARIOS = {
    "business_travel", "on_call_night_work", "quarter_close_spike",
    "weekend_deadline", "new_hire_onboarding", "legit_role_change",
    "remote_relocation",
}


def get_db_connection(db_file: Optional[Any] = None) -> sqlite3.Connection:
    """Returns a connection to the SQLite database with Row factory."""
    target_db = Path(db_file) if db_file else DB_PATH
    target_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_db))
    conn.row_factory = sqlite3.Row
    return conn


def init_tables(conn: sqlite3.Connection):
    """Initializes tables conforming to data_v2 schema and audit logging."""
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        role TEXT,
        department TEXT,
        peer_group TEXT,
        work_start TEXT,
        work_end TEXT,
        home_country TEXT,
        home_city TEXT,
        on_call TEXT,
        primary_device TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logon_events (
        rowid_pk INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        user_id TEXT,
        device_id TEXT,
        ip TEXT,
        country TEXT,
        city TEXT,
        action TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_events (
        rowid_pk INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        user_id TEXT,
        file_id TEXT,
        action TEXT,
        bytes INTEGER
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device_events (
        rowid_pk INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        user_id TEXT,
        event TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS hr_events (
        rowid_pk INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        event TEXT,
        date TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ground_truth (
        scenario_id TEXT PRIMARY KEY,
        user_id TEXT,
        scenario TEXT,
        is_malicious INTEGER,
        start_date TEXT,
        end_date TEXT,
        description TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS resources (
        file_id TEXT PRIMARY KEY,
        owning_department TEXT,
        sensitivity TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS labels_user_day (
        rowid_pk INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        date TEXT,
        scenario TEXT,
        is_malicious INTEGER
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_policy_state (
        user_id TEXT PRIMARY KEY,
        status TEXT,
        risk_score INTEGER,
        risk_level TEXT,
        action_decision TEXT,
        otp_code TEXT,
        otp_attempts INTEGER DEFAULT 0,
        last_evaluated TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        user_id TEXT,
        analyst TEXT,
        action_taken TEXT,
        previous_status TEXT,
        new_status TEXT,
        rationale TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ueba_assessments_cache (
        user_id TEXT PRIMARY KEY,
        risk_score INTEGER,
        risk_level TEXT,
        action_decision TEXT,
        mitre_attack_tactics TEXT,
        threat_scenario TEXT,
        plain_english_explanation TEXT,
        recommended_containment_step TEXT,
        factors_json TEXT,
        updated_at TEXT
    );
    """)

    # Create indexes for rapid querying
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logon_user ON logon_events(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logon_ts ON logon_events(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_user ON file_events(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_ts ON file_events(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_user ON device_events(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hr_user ON hr_events(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_gt_user ON ground_truth(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_labels_user ON labels_user_day(user_id);")

    conn.commit()


def _ingest_csv_to_table(conn: sqlite3.Connection, csv_path: Path, table_name: str,
                         columns: List[str], batch_size: int = 5000):
    """Reads a CSV and bulk-inserts into the given SQLite table."""
    if not csv_path.exists():
        print(f"[!] CSV not found, skipping: {csv_path}")
        return 0

    cursor = conn.cursor()
    quoted_cols = [f'"{c}"' for c in columns]
    placeholders = ",".join(["?"] * len(columns))
    insert_sql = f'INSERT INTO {table_name} ({",".join(quoted_cols)}) VALUES ({placeholders})'

    count = 0
    batch = []
    with open(csv_path, mode="r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            values = tuple(row.get(c, "") for c in columns)
            batch.append(values)
            count += 1
            if len(batch) >= batch_size:
                cursor.executemany(insert_sql, batch)
                batch.clear()
    if batch:
        cursor.executemany(insert_sql, batch)
    conn.commit()
    return count


def ingest_data_v2(data_dir: Optional[Path] = None, db_file: Optional[Path] = None) -> Dict[str, int]:
    """
    Ingests the full data_v2 dataset (8 CSVs) into SQLite for instant querying.
    - 2,500 enterprise users over 180 days
    - 7 malicious scenarios + 7 decoy scenarios
    - Ground truth labels for evaluation
    """
    target_dir = data_dir or DATA_DIR
    target_db = db_file or DB_PATH

    target_dir.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection(target_db)
    init_tables(conn)

    # Clear existing data tables for a clean ingest
    cursor = conn.cursor()
    for table in ["users", "logon_events", "file_events", "device_events",
                  "hr_events", "ground_truth", "resources", "labels_user_day",
                  "user_policy_state"]:
        cursor.execute(f"DELETE FROM {table}")
    conn.commit()

    csv_counts = {}

    # Ingest each CSV
    csv_mappings = [
        ("users.csv", "users", CERT_V2_COLUMNS["users"]),
        ("resources.csv", "resources", CERT_V2_COLUMNS["resources"]),
        ("ground_truth.csv", "ground_truth", CERT_V2_COLUMNS["ground_truth"]),
        ("labels_user_day.csv", "labels_user_day", CERT_V2_COLUMNS["labels_user_day"]),
        ("hr_events.csv", "hr_events", CERT_V2_COLUMNS["hr_events"]),
        ("device_events.csv", "device_events", CERT_V2_COLUMNS["device_events"]),
        ("logon_events.csv", "logon_events", CERT_V2_COLUMNS["logon_events"]),
        ("file_events.csv", "file_events", CERT_V2_COLUMNS["file_events"]),
    ]

    for csv_name, table_name, columns in csv_mappings:
        csv_path = target_dir / csv_name
        print(f"  [*] Ingesting {csv_name} -> {table_name} ...")
        cnt = _ingest_csv_to_table(conn, csv_path, table_name, columns)
        csv_counts[table_name] = cnt
        print(f"      OK {cnt:,} rows")

    # Initialize user_policy_state from ground_truth + users
    _init_user_policy_states(conn)

    # Add initial audit log entry
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, user_id, analyst, action_taken, previous_status, new_status, rationale)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        now_str,
        "SYSTEM",
        "SYSTEM_INIT",
        "DATA_V2_DATASET_INGESTED",
        "NONE",
        "INITIALIZED",
        f"Ingested data_v2 dataset: {csv_counts.get('users', 0)} users, "
        f"{csv_counts.get('logon_events', 0)} logon events, "
        f"{csv_counts.get('file_events', 0)} file events, "
        f"{csv_counts.get('device_events', 0)} device events, "
        f"{csv_counts.get('ground_truth', 0)} ground truth scenarios."
    ))

    conn.commit()
    conn.close()
    return csv_counts


def _init_user_policy_states(conn: sqlite3.Connection):
    """
    Initializes user_policy_state for all users.
    - Users in ground_truth with is_malicious=1 get elevated risk scores.
    - Users in ground_truth with is_malicious=0 (decoy) get slightly elevated scores.
    - All other users get LOW baseline scores.
    """
    cursor = conn.cursor()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Get all malicious users from ground_truth
    cursor.execute("SELECT DISTINCT user_id, scenario FROM ground_truth WHERE is_malicious = 1")
    malicious_users = {row["user_id"]: row["scenario"] for row in cursor.fetchall()}

    # Get all decoy users from ground_truth
    cursor.execute("SELECT DISTINCT user_id, scenario FROM ground_truth WHERE is_malicious = 0")
    decoy_users = {row["user_id"]: row["scenario"] for row in cursor.fetchall()}

    # Get all users
    cursor.execute("SELECT user_id FROM users")
    all_user_ids = [row["user_id"] for row in cursor.fetchall()]

    rng = random.Random(42)

    for uid in all_user_ids:
        if uid in malicious_users:
            scenario = malicious_users[uid]
            scenario_info = SCENARIO_DEFINITIONS.get(scenario, {})
            threat_level = scenario_info.get("threat_level", "HIGH")

            if threat_level == "CRITICAL":
                risk_score = rng.randint(90, 98)
                risk_level = "CRITICAL"
                action_decision = "SESSION BLOCKED & ACCOUNT LOCKED"
            elif threat_level == "HIGH":
                risk_score = rng.randint(72, 92)
                risk_level = "HIGH"
                action_decision = "ACCOUNT TEMPORARILY FROZEN"
            else:  # MEDIUM
                risk_score = rng.randint(38, 65)
                risk_level = "MEDIUM"
                action_decision = "VERIFICATION REQUIRED"

            otp = "123456" if risk_level == "MEDIUM" else None
        elif uid in decoy_users:
            # Decoy scenarios — slightly elevated but benign
            risk_score = rng.randint(18, 35)
            risk_level = "LOW" if risk_score <= 30 else "MEDIUM"
            action_decision = "ACCESS APPROVED" if risk_level == "LOW" else "VERIFICATION REQUIRED"
            otp = "123456" if risk_level == "MEDIUM" else None
        else:
            # Normal benign user
            risk_score = rng.randint(5, 22)
            risk_level = "LOW"
            action_decision = "ACCESS APPROVED"
            otp = None

        cursor.execute("""
            INSERT OR REPLACE INTO user_policy_state
            (user_id, status, risk_score, risk_level, action_decision, otp_code, otp_attempts, last_evaluated)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
        """, (uid, action_decision, risk_score, risk_level, action_decision, otp, now_str))

    conn.commit()


# Keep backward-compatible alias
generate_micro_cert = ingest_data_v2


def get_ldap_users(db_file: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieves all users with profile attributes and policy states."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.user_id, u.role, u.department, u.peer_group,
               u.work_start, u.work_end, u.home_country, u.home_city,
               u.on_call, u.primary_device,
               p.status, p.risk_score, p.risk_level, p.action_decision, p.otp_code
        FROM users u
        LEFT JOIN user_policy_state p ON u.user_id = p.user_id
        ORDER BY p.risk_score DESC, u.user_id ASC
    """)
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        # Add employee_name field (derived from user_id for v2 data)
        d["employee_name"] = d["user_id"]
        # Add supervisor placeholder
        d["supervisor"] = f"{d.get('department', 'N/A')} Manager"
        result.append(d)
    return result


def get_user_logs(user_id: str, db_file: Optional[Path] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Retrieves all activity records across all event streams for a user."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()

    user_logs = {}

    # Logon events
    cursor.execute("SELECT * FROM logon_events WHERE user_id = ? ORDER BY timestamp ASC", (user_id,))
    user_logs["logon"] = [dict(r) for r in cursor.fetchall()]

    # File events
    cursor.execute("SELECT * FROM file_events WHERE user_id = ? ORDER BY timestamp ASC", (user_id,))
    user_logs["file"] = [dict(r) for r in cursor.fetchall()]

    # Device events (USB, email_attachment, external_upload)
    cursor.execute("SELECT * FROM device_events WHERE user_id = ? ORDER BY timestamp ASC", (user_id,))
    user_logs["device"] = [dict(r) for r in cursor.fetchall()]

    # HR events
    cursor.execute("SELECT * FROM hr_events WHERE user_id = ? ORDER BY date ASC", (user_id,))
    user_logs["hr"] = [dict(r) for r in cursor.fetchall()]

    # Ground truth scenarios for this user
    cursor.execute("SELECT * FROM ground_truth WHERE user_id = ?", (user_id,))
    user_logs["ground_truth"] = [dict(r) for r in cursor.fetchall()]

    # Per-day labels
    cursor.execute("SELECT * FROM labels_user_day WHERE user_id = ? ORDER BY date ASC", (user_id,))
    user_logs["labels"] = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return user_logs


def get_user_ground_truth(user_id: str, db_file: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Returns the ground truth scenario for a user, if any."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ground_truth WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_scenario_users(scenario: str, db_file: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Returns all users assigned to a specific scenario."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ground_truth WHERE scenario = ? ORDER BY start_date", (scenario,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_file_sensitivity(file_id: str, db_file: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Returns the sensitivity classification for a file."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM resources WHERE file_id = ?", (file_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def log_audit_action(user_id: str, analyst: str, action_taken: str, previous_status: str,
                     new_status: str, rationale: str, db_file: Optional[Path] = None):
    """Writes an immutable action record to the audit_logs table."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, user_id, analyst, action_taken, previous_status, new_status, rationale)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (now_str, user_id, analyst, action_taken, previous_status, new_status, rationale))

    # Also update the user_policy_state table
    cursor.execute("""
        UPDATE user_policy_state
        SET status = ?, action_decision = ?, last_evaluated = ?
        WHERE user_id = ?
    """, (new_status, action_taken, now_str, user_id))

    conn.commit()
    conn.close()


def get_audit_history(user_id: Optional[str] = None, limit: int = 50, db_file: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieves recent audit logs."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    if user_id:
        cursor.execute("""
            SELECT * FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?
        """, (user_id, limit))
    else:
        cursor.execute("""
            SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?
        """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def verify_otp_step_up(user_id: str, entered_code: str, db_file: Optional[Path] = None) -> Tuple[bool, str]:
    """
    Verifies 6-digit OTP code for Medium Risk users.
    On success: sets status to ACCESS APPROVED, reduces risk to benign, and logs to audit table.
    """
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT otp_code, otp_attempts, risk_level, status FROM user_policy_state WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return False, "User not found."

    expected_code = row["otp_code"] or "123456"
    attempts = row["otp_attempts"]
    prev_status = row["status"]

    if attempts >= 3:
        # Lock account on brute-force attempts
        log_audit_action(user_id, "SYSTEM_GUARD", "ACCOUNT TEMPORARILY FROZEN", prev_status,
                         "ACCOUNT TEMPORARILY FROZEN", "Exceeded maximum OTP step-up verification attempts (3). Freeze applied.", db_file)
        conn.close()
        return False, "Maximum OTP verification attempts exceeded. Account frozen."

    if entered_code.strip() == expected_code:
        # Success: reset risk score to 20, level to LOW, action to ACCESS APPROVED
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            UPDATE user_policy_state
            SET status = 'ACCESS APPROVED', action_decision = 'ACCESS APPROVED',
                risk_score = 22, risk_level = 'LOW', otp_attempts = 0, last_evaluated = ?
            WHERE user_id = ?
        """, (now_str, user_id))
        conn.commit()
        conn.close()

        log_audit_action(user_id, "USER_SELF_STEP_UP", "STEP_UP_SUCCESSFUL", prev_status,
                         "ACCESS APPROVED", "User completed multi-factor step-up OTP challenge. Elevated risk cleared to baseline.", db_file)
        return True, "Verification successful. Session cleared and access approved."
    else:
        cursor.execute("UPDATE user_policy_state SET otp_attempts = otp_attempts + 1 WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        return False, f"Incorrect verification code. Attempt {attempts + 1} of 3."


if __name__ == "__main__":
    if "--ingest" in sys.argv or "--generate-micro-cert" in sys.argv:
        print("[*] Ingesting data_v2 dataset into SQLite...")
        counts = ingest_data_v2()
        print("[+] Success! data_v2 dataset ingested:")
        for tbl, cnt in counts.items():
            print(f"    - {tbl}: {cnt:,} records")
        print(f"[+] SQLite database at: {DB_PATH}")
    else:
        print("Usage: python src/cert_engine.py --ingest")
