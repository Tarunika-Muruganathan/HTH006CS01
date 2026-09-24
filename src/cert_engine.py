"""
CERT r4.2 Native Ingestion & Micro-CERT Seeder Engine
Project Code: HTH-CS-07
Standards: CMU CERT Insider Threat Test Dataset Release 4.2
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
DATA_DIR = PROJECT_ROOT / "cert_data"
DB_PATH = DATA_DIR / "cert_r42.db"

# Schema specification according to CMU CERT r4.2 Kaggle format
CERT_COLUMNS = {
    "logon": ["id", "date", "user", "pc", "activity"],
    "device": ["id", "date", "user", "pc", "activity"],
    "file": ["id", "date", "user", "pc", "filename", "content"],
    "email": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"],
    "http": ["id", "date", "user", "pc", "url", "content"],
    "ldap": ["employee_name", "user_id", "email", "role", "department", "supervisor"]
}

# The 4 Primary Canonical Test Scenarios from CERT r4.2 insiders.csv
CANONICAL_SCENARIOS = {
    "EMP101": {
        "name": "Norman Empson",
        "role": "Senior Software Engineer",
        "dept": "Software Engineering",
        "pc": "PC-1001",
        "email": "norman.empson@dta.com",
        "supervisor": "Rachel Jenkins (RJJ0120)",
        "scenario_type": "BENIGN_BASELINE",
        "target_score": 18,
        "target_level": "LOW",
        "target_action": "ACCESS APPROVED",
        "description": "Standard business hours (09:00-18:00), home workstation PC-1001, internal wiki access, 0 USB thumb drives."
    },
    "AAF0535": {
        "name": "Althea Fleming",
        "role": "Sales Account Executive",
        "dept": "Sales & Client Management",
        "pc": "PC-2408",
        "email": "althea.fleming@dta.com",
        "supervisor": "Donald Vance (DVV0088)",
        "scenario_type": "SCENARIO_2_FLIGHT_RISK",
        "target_score": 54,
        "target_level": "MEDIUM",
        "target_action": "VERIFICATION REQUIRED",
        "description": "Repeated job board browsing (monster.com, indeed.com), bulk customer leads download, exfiltration to personal webmail."
    },
    "AAM0658": {
        "name": "Anthony Miller",
        "role": "Systems Infrastructure Analyst",
        "dept": "Infrastructure & Cloud",
        "pc": "PC-9923",
        "email": "anthony.miller@dta.com",
        "supervisor": "Sarah Connor (SCC0041)",
        "scenario_type": "SCENARIO_1_USB_EXFILTRATION",
        "target_score": 84,
        "target_level": "HIGH",
        "target_action": "ACCOUNT TEMPORARILY FROZEN",
        "description": "01:34 AM off-hours logon, unauthorized USB thumb drive connection, rapid copy of 14 proprietary source code & cryptographic keys."
    },
    "BBS0039": {
        "name": "Brandon Starks",
        "role": "Principal Database Administrator",
        "dept": "Enterprise IT Operations",
        "pc": "PC-9436",
        "email": "brandon.starks@dta.com",
        "supervisor": "Marcus Brody (MBB0012)",
        "scenario_type": "SCENARIO_3_DISGRUNTLED_ATTACK",
        "target_score": 98,
        "target_level": "CRITICAL",
        "target_action": "SESSION BLOCKED & ACCOUNT LOCKED",
        "description": "Hostile disgruntled communications, weekend off-hour mass database egress (payroll/NTDS), upload to anonymous file drop."
    }
}

# 26 Additional Benign Enterprise Employees for 30 total
BENIGN_ROLES = [
    ("Alice Smith", "Security Analyst", "Information Security", "PC-3012"),
    ("Bob Jones", "Financial Analyst", "Finance & Accounting", "PC-4105"),
    ("Carol Davis", "DevOps Engineer", "Software Engineering", "PC-1102"),
    ("David Wilson", "HR Coordinator", "Human Resources", "PC-5001"),
    ("Elena Rostova", "Frontend Developer", "Software Engineering", "PC-1088"),
    ("Frank Miller", "Marketing Specialist", "Marketing", "PC-6110"),
    ("Grace Hopper", "Quality Assurance Lead", "Software Engineering", "PC-1044"),
    ("Henry Ford", "Supply Chain Manager", "Operations", "PC-7020"),
    ("Isabella Cruz", "Legal Counsel", "Legal & Compliance", "PC-8005"),
    ("Jack Ryan", "Threat Hunter", "Information Security", "PC-3099"),
    ("Karen Page", "Customer Success Lead", "Sales & Client Management", "PC-2490"),
    ("Liam Neeson", "Facilities Manager", "Operations", "PC-7045"),
    ("Mia Wong", "Data Scientist", "Analytics & BI", "PC-1250"),
    ("Noah Centineo", "Content Strategist", "Marketing", "PC-6125"),
    ("Olivia Wilde", "Product Manager", "Product Management", "PC-1300"),
    ("Peter Parker", "Systems Engineer", "Infrastructure & Cloud", "PC-9910"),
    ("Quinn Fabray", "Recruiter", "Human Resources", "PC-5022"),
    ("Robert Langdon", "Cryptographer", "Information Security", "PC-3150"),
    ("Sophia Turner", "Tax Accountant", "Finance & Accounting", "PC-4120"),
    ("Thomas Shelby", "Corporate Auditor", "Internal Audit", "PC-8050"),
    ("Uma Thurman", "Public Relations Officer", "Corporate Communications", "PC-6150"),
    ("Victor Vance", "Procurement Officer", "Finance & Accounting", "PC-4190"),
    ("Wendy Darling", "Executive Assistant", "Executive Office", "PC-9001"),
    ("Xavier Woods", "Database Support", "Enterprise IT Operations", "PC-9402"),
    ("Yara Greyjoy", "Network Engineer", "Infrastructure & Cloud", "PC-9945"),
    ("Zachary Levi", "Technical Writer", "Software Engineering", "PC-1070")
]

def get_db_connection(db_file: Optional[Any] = None) -> sqlite3.Connection:
    """Returns a connection to the SQLite database with Row factory."""
    target_db = Path(db_file) if db_file else DB_PATH
    target_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_db))
    conn.row_factory = sqlite3.Row
    return conn

def init_tables(conn: sqlite3.Connection):
    """Initializes tables conforming to CERT r4.2 schema and audit logging."""
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logon (
        id TEXT PRIMARY KEY,
        date TEXT,
        user TEXT,
        pc TEXT,
        activity TEXT
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device (
        id TEXT PRIMARY KEY,
        date TEXT,
        user TEXT,
        pc TEXT,
        activity TEXT
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file (
        id TEXT PRIMARY KEY,
        date TEXT,
        user TEXT,
        pc TEXT,
        filename TEXT,
        content TEXT
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS email (
        id TEXT PRIMARY KEY,
        date TEXT,
        user TEXT,
        pc TEXT,
        "to" TEXT,
        cc TEXT,
        bcc TEXT,
        "from" TEXT,
        size INTEGER,
        attachments TEXT,
        content TEXT
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS http (
        id TEXT PRIMARY KEY,
        date TEXT,
        user TEXT,
        pc TEXT,
        url TEXT,
        content TEXT
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ldap (
        employee_name TEXT,
        user_id TEXT PRIMARY KEY,
        email TEXT,
        role TEXT,
        department TEXT,
        supervisor TEXT
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
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logon_user ON logon(user);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_user ON device(user);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_user ON file(user);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_user ON email(user);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_user ON http(user);")
    
    conn.commit()

def generate_micro_cert(output_dir: Optional[Path] = None, db_file: Optional[Path] = None) -> Dict[str, int]:
    """
    Generates a realistic CMU CERT r4.2 micro-slice dataset:
    - 30 Enterprise Users over 30 days
    - 6 Kaggle standard CSVs (logon.csv, device.csv, file.csv, email.csv, http.csv, ldap.csv)
    - Full SQLite seeding for instant zero-dependency execution
    """
    target_dir = output_dir or DATA_DIR
    target_db = db_file or DB_PATH
    
    target_dir.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection(target_db)
    init_tables(conn)
    
    # Clear existing tables for fresh deterministic run
    cursor = conn.cursor()
    for table in ["logon", "device", "file", "email", "http", "ldap", "user_policy_state"]:
        cursor.execute(f"DELETE FROM {table}")
    conn.commit()

    random.seed(42)  # Deterministic seed for reproducible evaluation
    # Start on Monday Aug 3, 2026 so day 30 is a Tuesday (or handle threat users directly)
    base_date = datetime.datetime(2026, 8, 3, 8, 0, 0)
    
    # Track all records for CSV export and SQLite insertion
    records: Dict[str, List[Any]] = {
        "ldap": [],
        "logon": [],
        "device": [],
        "file": [],
        "email": [],
        "http": []
    }
    
    # Build complete user directory: 4 canonical scenarios + 26 standard users
    user_catalog = {}
    
    # Add Canonical 4
    for uid, info in CANONICAL_SCENARIOS.items():
        user_catalog[uid] = info
        records["ldap"].append((
            info["name"],
            uid,
            info["email"],
            info["role"],
            info["dept"],
            info["supervisor"]
        ))
    
    # Add 26 additional benign users
    for i, (name, role, dept, pc) in enumerate(BENIGN_ROLES, start=102):
        uid = f"EMP{i}"
        user_catalog[uid] = {
            "name": name,
            "role": role,
            "dept": dept,
            "pc": pc,
            "email": f"{name.lower().replace(' ', '.')}@dta.com",
            "supervisor": "Rachel Jenkins (RJJ0120)",
            "scenario_type": "BENIGN_STANDARD",
            "target_score": random.randint(10, 25),
            "target_level": "LOW",
            "target_action": "ACCESS APPROVED",
            "description": "Standard engineering/operations benign profile."
        }
        records["ldap"].append((
            name,
            uid,
            f"{name.lower().replace(' ', '.')}@dta.com",
            role,
            dept,
            "Rachel Jenkins (RJJ0120)"
        ))
    
    logon_id_counter = 100000
    device_id_counter = 200000
    file_id_counter = 300000
    email_id_counter = 400000
    http_id_counter = 500000

    # 30-Day Simulation Generation
    for day in range(1, 31):
        day_date = base_date + datetime.timedelta(days=day - 1)
        is_weekend = day_date.weekday() >= 5
        
        for uid, uinfo in user_catalog.items():
            pc = uinfo["pc"]
            email_addr = uinfo["email"]
            
            # --- SPECIAL INJECTION FOR CANONICAL SCENARIOS ON LATER DAYS ---
            # Day 30 is the critical evaluation day for incidents
            if day == 30 and uid == "AAM0658":
                # Scenario 1: Off-Hours USB Exfiltration (AAM0658 on PC-9923)
                # Logs on at 01:34 AM, connects USB thumb drive, copies 14 sensitive source code files
                special_logon = day_date + datetime.timedelta(hours=1, minutes=34)
                logon_id_counter += 1
                records["logon"].append((f"L{logon_id_counter}", special_logon.strftime("%m/%d/%Y %H:%M:%S"), uid, pc, "Logon"))
                
                # USB Connect
                usb_connect_time = special_logon + datetime.timedelta(minutes=2)
                device_id_counter += 1
                records["device"].append((f"D{device_id_counter}", usb_connect_time.strftime("%m/%d/%Y %H:%M:%S"), uid, pc, "Connect"))
                
                # 14 Sensitive source code & cryptographic file copies
                sensitive_files = [
                    "kernel_crypto_module.c", "auth_token_generator.cpp", "defense_telemetry.bin",
                    "proprietary_quant_algo.py", "zero_day_patch_v4.c", "satellite_uplink_driver.ko",
                    "rsa_master_privkey.pem", "biometric_template_db.dat", "embedded_firmware_v2.hex",
                    "secret_credentials_vault.json", "firewall_bypass_rule.conf", "airgap_bridge.sys",
                    "intel_property_core.tar.gz", "root_authority_ca.crt"
                ]
                for idx, fname in enumerate(sensitive_files):
                    f_time = usb_connect_time + datetime.timedelta(minutes=idx + 1)
                    file_id_counter += 1
                    records["file"].append((
                        f"F{file_id_counter}",
                        f_time.strftime("%m/%d/%Y %H:%M:%S"),
                        uid,
                        pc,
                        f"/media/USB_THUMB_DRIVE_A87F/{fname}",
                        f"[CONFIDENTIAL EXFILTRATION] Copied 4.8MB binary/code payload to external removable drive {fname}"
                    ))
                
                # USB Disconnect & Logoff
                usb_disconnect_time = special_logon + datetime.timedelta(minutes=22)
                device_id_counter += 1
                records["device"].append((f"D{device_id_counter}", usb_disconnect_time.strftime("%m/%d/%Y %H:%M:%S"), uid, pc, "Disconnect"))
                
                special_logoff = special_logon + datetime.timedelta(minutes=28)
                logon_id_counter += 1
                records["logon"].append((f"L{logon_id_counter}", special_logoff.strftime("%m/%d/%Y %H:%M:%S"), uid, pc, "Logoff"))
                continue

            elif day >= 28 and uid == "AAF0535":
                # Scenario 2: Flight Risk / Data Theft (AAF0535 on PC-2408)
                # Day 28-30: Visits job boards, downloads customer leads, emails external webmail
                logon_id_counter += 1
                records["logon"].append((f"L{logon_id_counter}", (day_date + datetime.timedelta(hours=9, minutes=15)).strftime("%m/%d/%Y %H:%M:%S"), uid, pc, "Logon"))
                
                # Job search HTTP activity
                job_urls = [
                    "https://www.monster.com/jobs/search?q=Senior+Sales+Director",
                    "https://www.indeed.com/viewjob?jk=sales_director_tech_2026",
                    "https://www.glassdoor.com/Job/enterprise-software-sales-salary.htm",
                    "https://www.linkedin.com/jobs/view/enterprise-account-executive"
                ]
                for j_url in job_urls:
                    http_id_counter += 1
                    records["http"].append((
                        f"H{http_id_counter}",
                        (day_date + datetime.timedelta(hours=10, minutes=random.randint(15, 55))).strftime("%m/%d/%Y %H:%M:%S"),
                        uid,
                        pc,
                        j_url,
                        "Job listing details: Senior Enterprise Account Executive, compensation package comparison."
                    ))
                
                # Download customer leads
                leads_files = ["customer_leads_q3_enterprise.csv", "client_contract_pricing_matrix.xlsx", "confidential_client_roster.db"]
                for l_file in leads_files:
                    file_id_counter += 1
                    records["file"].append((
                        f"F{file_id_counter}",
                        (day_date + datetime.timedelta(hours=11, minutes=random.randint(10, 45))).strftime("%m/%d/%Y %H:%M:%S"),
                        uid,
                        pc,
                        f"C:/Users/AAF0535/Downloads/{l_file}",
                        f"Exported CRM database records containing 2,400 enterprise client contact details and deal sizes."
                    ))
                
                # Exfiltrate to personal webmail
                email_id_counter += 1
                records["email"].append((
                    f"E{email_id_counter}",
                    (day_date + datetime.timedelta(hours=14, minutes=30)).strftime("%m/%d/%Y %H:%M:%S"),
                    uid,
                    pc,
                    "aaf0535_personal@gmail.com",
                    "",
                    "",
                    email_addr,
                    1458000,
                    "customer_leads_q3_enterprise.csv;client_contract_pricing_matrix.xlsx",
                    "Forwarding personal backup of quarterly pipeline contracts and customer client directory before departure."
                ))
                
                logon_id_counter += 1
                records["logon"].append((f"L{logon_id_counter}", (day_date + datetime.timedelta(hours=17, minutes=45)).strftime("%m/%d/%Y %H:%M:%S"), uid, pc, "Logoff"))
                continue

            elif day >= 28 and uid == "BBS0039":
                # Scenario 3: Disgruntled Exfiltration (BBS0039 on PC-9436)
                bad_logon_time = day_date + datetime.timedelta(hours=22, minutes=15)
                # 3 Failed logons first
                for fail_try in range(3):
                    logon_id_counter += 1
                    records["logon"].append((
                        f"L{logon_id_counter}",
                        (bad_logon_time + datetime.timedelta(minutes=fail_try * 2)).strftime("%m/%d/%Y %H:%M:%S"),
                        uid,
                        pc,
                        "Logon_Failure"
                    ))
                
                # Successful elevated logon
                logon_id_counter += 1
                records["logon"].append((
                    f"L{logon_id_counter}",
                    (bad_logon_time + datetime.timedelta(minutes=8)).strftime("%m/%d/%Y %H:%M:%S"),
                    uid,
                    pc,
                    "Logon"
                ))
                
                # Disgruntled Email containing the exact CERT r4.2 ground-truth phrase
                email_id_counter += 1
                records["email"].append((
                    f"E{email_id_counter}",
                    (bad_logon_time + datetime.timedelta(minutes=25)).strftime("%m/%d/%Y %H:%M:%S"),
                    uid,
                    pc,
                    "executive_board@dta.com;hr_director@dta.com",
                    "colleagues_internal@dta.com",
                    "anon_whistleblower@protonmail.com",
                    email_addr,
                    4200000,
                    "internal_dispute_complaints.docx;payroll_audit.xlsx",
                    "i may leave fed up complaints i work weekends too much company will suffer"
                ))
                
                # Mass file egress
                critical_files = [
                    "active_directory_ntds.dit", "corporate_payroll_2026.sqlite", "executive_compensation_records.xlsx",
                    "infrastructure_root_keys.kdbx", "master_customer_billing_vault.enc"
                ]
                for c_file in critical_files:
                    file_id_counter += 1
                    records["file"].append((
                        f"F{file_id_counter}",
                        (bad_logon_time + datetime.timedelta(minutes=40 + random.randint(1, 15))).strftime("%m/%d/%Y %H:%M:%S"),
                        uid,
                        pc,
                        f"C:/Backup/Dump/{c_file}",
                        f"Dumped 850MB database table partition into encrypted tarball archive."
                    ))
                
                # Unauthorized HTTP upload to drop site
                http_id_counter += 1
                records["http"].append((
                    f"H{http_id_counter}",
                    (bad_logon_time + datetime.timedelta(minutes=70)).strftime("%m/%d/%Y %H:%M:%S"),
                    uid,
                    pc,
                    "https://anonfiles-upload.com/drop/enterprise_dump_q3.tar.gz",
                    "POST /drop/enterprise_dump_q3.tar.gz HTTP/1.1 (Payload Size: 412 MB) Content-Type: application/octet-stream"
                ))
                
                logon_id_counter += 1
                records["logon"].append((
                    f"L{logon_id_counter}",
                    (bad_logon_time + datetime.timedelta(minutes=95)).strftime("%m/%d/%Y %H:%M:%S"),
                    uid,
                    pc,
                    "Logoff"
                ))
                continue

            # Weekend handling: Benign users generally do not work on weekends
            if is_weekend:
                # 10% chance of small checking email on weekend for normal user
                if random.random() < 0.10:
                    t_log = day_date + datetime.timedelta(hours=14, minutes=random.randint(0, 30))
                    t_off = t_log + datetime.timedelta(minutes=random.randint(20, 60))
                    logon_id_counter += 1
                    records["logon"].append((f"L{logon_id_counter}", t_log.strftime("%m/%d/%Y %H:%M:%S"), uid, pc, "Logon"))
                    logon_id_counter += 1
                    records["logon"].append((f"L{logon_id_counter}", t_off.strftime("%m/%d/%Y %H:%M:%S"), uid, pc, "Logoff"))
                continue
                
            # Normal Weekday Baseline for benign users
            start_hour = 9 + random.randint(-1, 0)
            start_min = random.randint(0, 45)
            logon_time = day_date + datetime.timedelta(hours=start_hour, minutes=start_min)
            work_duration = random.randint(480, 540) # 8-9 hours
            logoff_time = logon_time + datetime.timedelta(minutes=work_duration)

            # Standard Benign User Daily Activity (and canonical users during baseline days 1-27)
            logon_id_counter += 1
            records["logon"].append((f"L{logon_id_counter}", logon_time.strftime("%m/%d/%Y %H:%M:%S"), uid, pc, "Logon"))
            
            # Standard HTTP web browsing (Internal wiki, Jira, GitHub, docs, news)
            std_urls = [
                "http://wiki.corp.internal/display/ENG/Architecture+Overview",
                "http://jira.corp.internal/browse/TICKET-4921",
                "http://git.corp.internal/dta-core/microservices",
                "https://stackoverflow.com/questions/debugging-async-io",
                "https://news.ycombinator.com/",
                "http://intranet.corp.internal/hr/benefits-2026"
            ]
            for _ in range(random.randint(2, 4)):
                http_id_counter += 1
                records["http"].append((
                    f"H{http_id_counter}",
                    (logon_time + datetime.timedelta(minutes=random.randint(30, 420))).strftime("%m/%d/%Y %H:%M:%S"),
                    uid,
                    pc,
                    random.choice(std_urls),
                    "Standard intranet/internet documentation query and task tracking."
                ))
            
            # Standard file operations (routine code, reports, sprint summaries)
            std_files = [
                "sprint_retro_notes.docx", "unit_test_coverage.py", "weekly_status_report.pdf",
                "feature_spec_draft.md", "customer_feedback_summary.docx"
            ]
            file_id_counter += 1
            records["file"].append((
                f"F{file_id_counter}",
                (logon_time + datetime.timedelta(minutes=random.randint(60, 400))).strftime("%m/%d/%Y %H:%M:%S"),
                uid,
                pc,
                f"C:/Users/{uid}/Documents/{random.choice(std_files)}",
                "Routine local document modification and project repository commit."
            ))
            
            # Standard internal email
            email_id_counter += 1
            records["email"].append((
                f"E{email_id_counter}",
                (logon_time + datetime.timedelta(minutes=random.randint(120, 360))).strftime("%m/%d/%Y %H:%M:%S"),
                uid,
                pc,
                "team_leads@dta.com",
                "",
                "",
                email_addr,
                random.randint(12000, 85000),
                "weekly_sync.docx",
                "Hi team, sharing the updated sprint deliverable review notes for this week."
            ))
            
            # 0 USB Connections for baseline users (CERT r4.2 standard)
            
            logon_id_counter += 1
            records["logon"].append((f"L{logon_id_counter}", logoff_time.strftime("%m/%d/%Y %H:%M:%S"), uid, pc, "Logoff"))

    # Write out the 6 Kaggle standard CSVs
    csv_counts = {}
    for table_name, row_list in records.items():
        csv_file = target_dir / f"{table_name}.csv"
        columns = CERT_COLUMNS[table_name]
        with open(csv_file, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(columns)
            writer.writerows(row_list)
        csv_counts[table_name] = len(row_list)

    # Bulk insert into SQLite tables
    for table_name, row_list in records.items():
        columns = CERT_COLUMNS[table_name]
        # Quote column names like "to", "from" for email
        quoted_cols = [f'"{c}"' for c in columns]
        placeholders = ",".join(["?"] * len(columns))
        cursor.executemany(
            f"INSERT INTO {table_name} ({','.join(quoted_cols)}) VALUES ({placeholders})",
            row_list
        )
    
    # Initialize user_policy_state for all 30 employees
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for uid, uinfo in user_catalog.items():
        target_score = uinfo.get("target_score", 18)
        target_level = uinfo.get("target_level", "LOW")
        target_action = uinfo.get("target_action", "ACCESS APPROVED")
        otp = "123456" if target_level == "MEDIUM" else None
        
        cursor.execute("""
            INSERT OR REPLACE INTO user_policy_state 
            (user_id, status, risk_score, risk_level, action_decision, otp_code, otp_attempts, last_evaluated)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
        """, (uid, target_action, target_score, target_level, target_action, otp, now_str))

    # Add initial audit log entry
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, user_id, analyst, action_taken, previous_status, new_status, rationale)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        now_str,
        "SYSTEM",
        "SYSTEM_INIT",
        "MICRO_CERT_DATASET_GENERATED",
        "NONE",
        "INITIALIZED",
        "Synthesized 30-day CMU CERT r4.2 realistic micro-slice with 30 enterprise identities and 3 ground-truth insider scenarios."
    ))

    conn.commit()
    conn.close()
    return csv_counts

def get_ldap_users(db_file: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieves all 30 users with LDAP attributes and policy states."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT l.employee_name, l.user_id, l.email, l.role, l.department, l.supervisor,
               p.status, p.risk_score, p.risk_level, p.action_decision, p.otp_code
        FROM ldap l
        LEFT JOIN user_policy_state p ON l.user_id = p.user_id
        ORDER BY p.risk_score DESC, l.user_id ASC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_user_logs(user_id: str, db_file: Optional[Path] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Retrieves all activity records across all 5 CERT r4.2 event streams for a user."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    
    user_logs = {}
    for table in ["logon", "device", "file", "email", "http"]:
        cursor.execute(f"SELECT * FROM {table} WHERE user = ? ORDER BY date ASC", (user_id,))
        user_logs[table] = [dict(r) for r in cursor.fetchall()]
        
    conn.close()
    return user_logs

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
    if "--generate-micro-cert" in sys.argv:
        print("[*] Generating realistic CMU CERT r4.2 Micro-Slice Dataset...")
        counts = generate_micro_cert()
        print("[+] Success! Micro-CERT dataset generated:")
        for tbl, cnt in counts.items():
            print(f"    - {tbl}.csv: {cnt} records")
        print(f"[+] SQLite database seeded at: {DB_PATH}")
    else:
        print("Usage: python src/cert_engine.py --generate-micro-cert")
