
import streamlit as st
import sqlite3
import csv
import io
import os
import json
import html
import hmac
import hashlib
import secrets
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, time, timedelta
from collections import defaultdict, Counter

st.set_page_config(
    page_title="CyberShield Enterprise SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(
    os.getenv(
        "CYBERSHIELD_DB_PATH",
        str(APP_DIR / "cybershield_soc_v2.db")
    )
)
APP_NAME = "CyberShield Enterprise SOC"
GROUP_NAME = "Group 13 | Project 20"
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5-mini")


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def escape(value):
    return html.escape(str(value))


def incident_number(value):
    return f"INC-{int(value):04d}"


def get_setting(name, default=None):
    value = os.getenv(name)
    if value:
        return value
    try:
        return st.secrets.get(name, default)
    except Exception:
        return default


def db_connection():
    connection = sqlite3.connect(
        DB_PATH,
        timeout=30
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def table_columns(connection, table):
    return {
        row["name"]
        for row in connection.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
    }


def initialize_database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with db_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee TEXT NOT NULL,
                login_time TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                unfamiliar_location INTEGER NOT NULL,
                successful_login INTEGER NOT NULL,
                risk TEXT NOT NULL,
                classification TEXT NOT NULL,
                explanation TEXT NOT NULL,
                decision TEXT NOT NULL DEFAULT 'Pending Review',
                notes TEXT NOT NULL DEFAULT '',
                account_verified INTEGER NOT NULL DEFAULT 0,
                employee_contacted INTEGER NOT NULL DEFAULT 0,
                evidence_reviewed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        columns = table_columns(connection, "incidents")

        additions = {
            "playbook_id": "TEXT",
            "playbook_reason": "TEXT",
            "playbook_source": "TEXT",
            "source_type": "TEXT DEFAULT 'Manual Alert'",
            "source_ip": "TEXT DEFAULT ''",
            "attack_type": "TEXT DEFAULT ''",
            "evidence_json": "TEXT DEFAULT '[]'",
            "assigned_to": "TEXT DEFAULT ''"
        }

        for column, column_type in additions.items():
            if column not in columns:
                connection.execute(
                    f"ALTER TABLE incidents "
                    f"ADD COLUMN {column} {column_type}"
                )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        audit_columns = table_columns(
            connection,
            "audit_events"
        )

        for column in ("previous_hash", "event_hash"):
            if column not in audit_columns:
                connection.execute(
                    f"ALTER TABLE audit_events "
                    f"ADD COLUMN {column} TEXT"
                )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS raw_log_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                record_count INTEGER NOT NULL,
                alert_count INTEGER NOT NULL DEFAULT 0,
                file_hash TEXT NOT NULL,
                uploaded_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS raw_log_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                location TEXT NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY(batch_id)
                    REFERENCES raw_log_batches(id)
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS integration_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_incidents_created
            ON incidents(created_at)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_incidents_risk
            ON incidents(risk)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_raw_events_batch
            ON raw_log_events(batch_id)
        """)


def audit_payload(event):
    return json.dumps(
        {
            "id": event["id"],
            "incident_id": event["incident_id"],
            "event_type": event["event_type"],
            "description": event["description"],
            "created_at": event["created_at"]
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    )


def calculate_audit_hash(previous_hash, payload):
    return hashlib.sha256(
        (previous_hash + payload).encode("utf-8")
    ).hexdigest()


def append_audit(
    connection,
    incident_id,
    event_type,
    description
):
    previous = connection.execute("""
        SELECT event_hash
        FROM audit_events
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    previous_hash = (
        previous["event_hash"]
        if previous and previous["event_hash"]
        else "GENESIS"
    )

    created = now_text()

    cursor = connection.execute("""
        INSERT INTO audit_events (
            incident_id,
            event_type,
            description,
            created_at,
            previous_hash,
            event_hash
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        incident_id,
        event_type,
        description,
        created,
        previous_hash,
        ""
    ))

    event_id = cursor.lastrowid

    payload = json.dumps(
        {
            "id": event_id,
            "incident_id": incident_id,
            "event_type": event_type,
            "description": description,
            "created_at": created
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    )

    event_hash = calculate_audit_hash(
        previous_hash,
        payload
    )

    connection.execute("""
        UPDATE audit_events
        SET event_hash = ?
        WHERE id = ?
    """, (event_hash, event_id))


def verify_audit_chain():
    with db_connection() as connection:
        events = [
            dict(row)
            for row in connection.execute("""
                SELECT *
                FROM audit_events
                ORDER BY id ASC
            """).fetchall()
        ]

    previous_hash = "GENESIS"
    legacy_count = 0

    for event in events:
        if not event.get("event_hash"):
            legacy_count += 1
            previous_hash = "GENESIS"
            continue

        if event.get("previous_hash") != previous_hash:
            return {
                "valid": False,
                "checked": len(events),
                "legacy": legacy_count,
                "message": "Audit chain mismatch detected."
            }

        expected = calculate_audit_hash(
            previous_hash,
            audit_payload(event)
        )

        if not hmac.compare_digest(
            expected,
            event["event_hash"]
        ):
            return {
                "valid": False,
                "checked": len(events),
                "legacy": legacy_count,
                "message": "Audit event integrity check failed."
            }

        previous_hash = event["event_hash"]

    return {
        "valid": True,
        "checked": len(events),
        "legacy": legacy_count,
        "message": (
            "Stored hash-linked events passed verification."
            if not legacy_count
            else "Hash-linked events checked; legacy records remain."
        )
    }


def assess_risk(attempts, unfamiliar, successful):
    if attempts >= 3 and unfamiliar and successful:
        return (
            "HIGH",
            "Potential Account Compromise",
            "Multiple failed authentication attempts "
            "were followed by a successful login "
            "from an unfamiliar location."
        )

    if attempts == 0 and not unfamiliar and successful:
        return (
            "LOW",
            "Normal Authentication Activity",
            "Authentication indicators match "
            "the low-risk detection policy."
        )

    return (
        "UNCLEAR",
        "Manual Investigation Required",
        "Available authentication indicators "
        "require additional analyst investigation."
    )


PLAYBOOKS = {
    "HIGH": {
        "id": "PB-002",
        "name": "Suspicious Authentication Investigation",
        "source": "CyberShield Internal Educational Playbook",
        "reason": "High-risk authentication indicators detected.",
        "steps": [
            "Validate the authentication evidence.",
            "Verify the affected account.",
            "Contact the employee through an approved channel.",
            "Recommend containment if compromise is confirmed.",
            "Escalate and document the investigation."
        ]
    },
    "LOW": {
        "id": "PB-001",
        "name": "Normal Authentication Monitoring",
        "source": "CyberShield Internal Educational Playbook",
        "reason": "Low-risk authentication indicators detected.",
        "steps": [
            "Document the authentication event.",
            "Continue routine monitoring."
        ]
    },
    "UNCLEAR": {
        "id": "PB-003",
        "name": "Evidence Collection and Manual Triage",
        "source": "CyberShield Internal Educational Playbook",
        "reason": "Additional investigation is required.",
        "steps": [
            "Collect available evidence.",
            "Review account and login context.",
            "Request analyst review.",
            "Reassess the event after investigation."
        ]
    }
}


def get_playbook(risk):
    return PLAYBOOKS.get(risk)


def create_incident(
    employee,
    login_time,
    attempts,
    unfamiliar,
    successful,
    source_type="Manual Alert",
    source_ip="",
    attack_type="",
    evidence=None
):
    risk, classification, explanation = assess_risk(
        attempts,
        unfamiliar,
        successful
    )

    if attack_type:
        classification = attack_type

        if attack_type in (
            "Brute Force",
            "Password Spraying",
            "Possible Account Compromise"
        ):
            risk = "HIGH"

        explanation = (
            f"Authentication log analysis identified "
            f"a potential {attack_type} pattern."
        )

    playbook = get_playbook(risk)
    created = now_text()

    with db_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO incidents (
                employee,
                login_time,
                failed_attempts,
                unfamiliar_location,
                successful_login,
                risk,
                classification,
                explanation,
                playbook_id,
                playbook_reason,
                playbook_source,
                source_type,
                source_ip,
                attack_type,
                evidence_json,
                created_at,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            employee,
            str(login_time),
            int(attempts),
            int(unfamiliar),
            int(successful),
            risk,
            classification,
            explanation,
            playbook["id"] if playbook else None,
            playbook["reason"] if playbook else "",
            playbook["source"] if playbook else "",
            source_type,
            source_ip,
            attack_type,
            json.dumps(
                evidence or [],
                ensure_ascii=False,
                default=str
            ),
            created,
            created
        ))

        incident_id = cursor.lastrowid

        append_audit(
            connection,
            incident_id,
            "INCIDENT_CREATED",
            f"Incident created with risk {risk}."
        )

    return incident_id


def enrich_incident(item):
    playbook = get_playbook(item["risk"])

    if playbook:
        item["playbook_id"] = (
            item.get("playbook_id") or playbook["id"]
        )
        item["playbook_reason"] = (
            item.get("playbook_reason") or playbook["reason"]
        )
        item["playbook_source"] = (
            item.get("playbook_source") or playbook["source"]
        )

    return item


def load_incidents():
    with db_connection() as connection:
        return [
            enrich_incident(dict(row))
            for row in connection.execute("""
                SELECT *
                FROM incidents
                ORDER BY id DESC
            """).fetchall()
        ]


def load_incident(incident_id):
    with db_connection() as connection:
        row = connection.execute("""
            SELECT *
            FROM incidents
            WHERE id = ?
        """, (incident_id,)).fetchone()

    return enrich_incident(dict(row)) if row else None


def load_audit_events():
    with db_connection() as connection:
        return [
            dict(row)
            for row in connection.execute("""
                SELECT *
                FROM audit_events
                ORDER BY id DESC
            """).fetchall()
        ]


def update_review(
    incident_id,
    decision,
    notes,
    verified,
    contacted,
    reviewed,
    assigned_to=""
):
    previous = load_incident(incident_id)

    if previous is None:
        return False

    updated = now_text()

    with db_connection() as connection:
        connection.execute("""
            UPDATE incidents
            SET decision = ?,
                notes = ?,
                account_verified = ?,
                employee_contacted = ?,
                evidence_reviewed = ?,
                assigned_to = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            decision,
            notes,
            int(verified),
            int(contacted),
            int(reviewed),
            assigned_to,
            updated,
            incident_id
        ))

        append_audit(
            connection,
            incident_id,
            "ANALYST_REVIEW",
            (
                f"Decision changed from "
                f"{previous['decision']} to {decision}."
            )
        )

    return True


def normalize_status(value):
    status = str(value).strip().lower()

    if status in (
        "failed",
        "failure",
        "fail",
        "denied",
        "invalid",
        "0"
    ):
        return "failed"

    if status in (
        "success",
        "successful",
        "succeeded",
        "passed",
        "1"
    ):
        return "success"

    return "unknown"


def parse_log_timestamp(value):
    value = str(value).strip()

    for pattern in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M"
    ):
        try:
            return datetime.strptime(value, pattern)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).replace(tzinfo=None)
    except ValueError:
        raise ValueError(
            f"Unsupported timestamp format: {value}"
        )


def validate_authentication_logs(raw_bytes):
    if len(raw_bytes) > 10 * 1024 * 1024:
        raise ValueError(
            "CSV file exceeds the 10 MB upload limit."
        )

    content = raw_bytes.decode("utf-8-sig")

    reader = csv.DictReader(io.StringIO(content))

    required = {
        "timestamp",
        "username",
        "source_ip",
        "location",
        "status"
    }

    columns = set(reader.fieldnames or [])
    missing = required - columns

    if missing:
        raise ValueError(
            "Missing required columns: "
            + ", ".join(sorted(missing))
        )

    logs = []

    for number, row in enumerate(reader, start=2):
        if None in row:
            raise ValueError(
                f"Invalid CSV structure at row {number}."
            )

        event = {
            key: str(row.get(key) or "").strip()
            for key in required
        }

        if not all(event.values()):
            raise ValueError(
                f"Missing required values at row {number}."
            )

        parsed = parse_log_timestamp(
            event["timestamp"]
        )

        event["timestamp"] = parsed.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        event["status"] = normalize_status(
            event["status"]
        )

        if event["status"] == "unknown":
            raise ValueError(
                f"Unknown authentication status at row {number}."
            )

        logs.append(event)

    if not logs:
        raise ValueError(
            "The uploaded CSV contains no log records."
        )

    if len(logs) > 50000:
        raise ValueError(
            "Maximum supported records per upload: 50,000."
        )

    return logs


def detect_authentication_threats(logs):
    events = []

    for log in logs:
        event = dict(log)
        event["_time"] = parse_log_timestamp(
            event["timestamp"]
        )
        event["_status"] = normalize_status(
            event["status"]
        )
        events.append(event)

    events.sort(key=lambda item: item["_time"])

    alerts = []
    signatures = set()

    by_user_ip = defaultdict(list)
    by_ip = defaultdict(list)
    by_user = defaultdict(list)

    for event in events:
        by_user_ip[
            (event["username"], event["source_ip"])
        ].append(event)

        by_ip[event["source_ip"]].append(event)
        by_user[event["username"]].append(event)

    for (username, source_ip), records in by_user_ip.items():
        failures = [
            event
            for event in records
            if event["_status"] == "failed"
        ]

        for start in range(len(failures)):
            beginning = failures[start]["_time"]

            window = [
                event
                for event in failures[start:]
                if timedelta(0) <= (
                    event["_time"] - beginning
                ) <= timedelta(minutes=10)
            ]

            if len(window) >= 5:
                signature = (
                    "Brute Force",
                    username,
                    source_ip
                )

                if signature not in signatures:
                    signatures.add(signature)

                    alerts.append({
                        "attack": "Brute Force",
                        "username": username,
                        "source_ip": source_ip,
                        "risk": "HIGH",
                        "failed_attempts": len(window),
                        "timestamp": window[-1]["timestamp"],
                        "reason": (
                            "Five or more failed login attempts "
                            "within ten minutes."
                        ),
                        "evidence": [
                            dict(
                                (key, value)
                                for key, value in item.items()
                                if not key.startswith("_")
                            )
                            for item in window
                        ]
                    })

                break

    for source_ip, records in by_ip.items():
        failures = [
            event
            for event in records
            if event["_status"] == "failed"
        ]

        for start in range(len(failures)):
            beginning = failures[start]["_time"]

            window = [
                event
                for event in failures[start:]
                if timedelta(0) <= (
                    event["_time"] - beginning
                ) <= timedelta(minutes=15)
            ]

            usernames = {
                event["username"]
                for event in window
            }

            if len(usernames) >= 3:
                signature = (
                    "Password Spraying",
                    source_ip
                )

                if signature not in signatures:
                    signatures.add(signature)

                    alerts.append({
                        "attack": "Password Spraying",
                        "username": ", ".join(
                            sorted(usernames)
                        ),
                        "source_ip": source_ip,
                        "risk": "HIGH",
                        "failed_attempts": len(window),
                        "timestamp": window[-1]["timestamp"],
                        "reason": (
                            "One source IP attempted failed "
                            "authentication against three "
                            "or more distinct accounts."
                        ),
                        "evidence": [
                            {
                                key: value
                                for key, value in item.items()
                                if not key.startswith("_")
                            }
                            for item in window
                        ]
                    })

                break

    for username, records in by_user.items():
        failures = [
            event
            for event in records
            if event["_status"] == "failed"
        ]

        successes = [
            event
            for event in records
            if event["_status"] == "success"
        ]

        for success in successes:
            recent_failures = [
                event
                for event in failures
                if timedelta(0) <= (
                    success["_time"] - event["_time"]
                ) <= timedelta(minutes=15)
            ]

            if len(recent_failures) < 3:
                continue

            signature = (
                "Possible Account Compromise",
                username,
                success["source_ip"]
            )

            if signature in signatures:
                continue

            signatures.add(signature)

            evidence = recent_failures + [success]

            alerts.append({
                "attack": "Possible Account Compromise",
                "username": username,
                "source_ip": success["source_ip"],
                "risk": "HIGH",
                "failed_attempts": len(recent_failures),
                "timestamp": success["timestamp"],
                "reason": (
                    "Successful authentication followed "
                    "three or more recent failures."
                ),
                "evidence": [
                    {
                        key: value
                        for key, value in item.items()
                        if not key.startswith("_")
                    }
                    for item in evidence
                ]
            })

            break

    return alerts


def save_log_batch(
    filename,
    raw_bytes,
    logs,
    alerts,
    uploaded_by
):
    file_hash = hashlib.sha256(
        raw_bytes
    ).hexdigest()

    with db_connection() as connection:
        existing = connection.execute("""
            SELECT id
            FROM raw_log_batches
            WHERE file_hash = ?
            LIMIT 1
        """, (file_hash,)).fetchone()

        if existing:
            return existing["id"], False

        cursor = connection.execute("""
            INSERT INTO raw_log_batches (
                filename,
                record_count,
                alert_count,
                file_hash,
                uploaded_by,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            filename,
            len(logs),
            len(alerts),
            file_hash,
            uploaded_by,
            now_text()
        ))

        batch_id = cursor.lastrowid

        connection.executemany("""
            INSERT INTO raw_log_events (
                batch_id,
                timestamp,
                username,
                source_ip,
                location,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, [
            (
                batch_id,
                event["timestamp"],
                event["username"],
                event["source_ip"],
                event["location"],
                event["status"]
            )
            for event in logs
        ])

        append_audit(
            connection,
            None,
            "RAW_LOG_BATCH_IMPORTED",
            (
                f"Imported batch {batch_id}: "
                f"{len(logs)} events and "
                f"{len(alerts)} detected patterns."
            )
        )

    return batch_id, True


def load_log_batches():
    with db_connection() as connection:
        return [
            dict(row)
            for row in connection.execute("""
                SELECT *
                FROM raw_log_batches
                ORDER BY id DESC
            """).fetchall()
        ]


def load_log_events(batch_id=None):
    with db_connection() as connection:
        if batch_id is None:
            rows = connection.execute("""
                SELECT *
                FROM raw_log_events
                ORDER BY id DESC
                LIMIT 5000
            """).fetchall()
        else:
            rows = connection.execute("""
                SELECT *
                FROM raw_log_events
                WHERE batch_id = ?
                ORDER BY id ASC
            """, (batch_id,)).fetchall()

    return [dict(row) for row in rows]


def create_incidents_from_alerts(alerts):
    created = []

    for alert in alerts:
        username = alert["username"].split(",")[0].strip()

        incident_id = create_incident(
            employee=username,
            login_time=alert["timestamp"],
            attempts=alert["failed_attempts"],
            unfamiliar=False,
            successful=(
                alert["attack"]
                == "Possible Account Compromise"
            ),
            source_type="Raw Log Analysis",
            source_ip=alert["source_ip"],
            attack_type=alert["attack"],
            evidence=alert.get("evidence", [])
        )

        created.append(incident_id)

    return created


def load_security_metrics():
    incidents = load_incidents()

    return {
        "total": len(incidents),
        "high": sum(
            item["risk"] == "HIGH"
            for item in incidents
        ),
        "low": sum(
            item["risk"] == "LOW"
            for item in incidents
        ),
        "unclear": sum(
            item["risk"] == "UNCLEAR"
            for item in incidents
        ),
        "approved": sum(
            item["decision"] == "Approve"
            for item in incidents
        ),
        "rejected": sum(
            item["decision"] == "Reject"
            for item in incidents
        ),
        "pending": sum(
            item["decision"] == "Pending Review"
            for item in incidents
        )
    }


def incident_report(item):
    return f"""
CYBERSHIELD ENTERPRISE SOC
SECURITY INCIDENT INVESTIGATION REPORT
==================================================

INCIDENT INFORMATION

Incident ID: {incident_number(item['id'])}
Employee Account: {item['employee']}
Login Time: {item['login_time']}
Failed Login Attempts: {item['failed_attempts']}
Unfamiliar Location: {'YES' if item['unfamiliar_location'] else 'NO'}
Successful Login: {'YES' if item['successful_login'] else 'NO'}
Source Type: {item.get('source_type') or 'Manual Alert'}
Source IP: {item.get('source_ip') or 'Not provided'}
Attack Type: {item.get('attack_type') or 'Not specified'}

RISK ASSESSMENT

Risk Level: {item['risk']}
Classification: {item['classification']}
Assessment: {item['explanation']}

RESPONSE PLAYBOOK

Playbook ID: {item.get('playbook_id') or 'N/A'}
Selection Reason: {item.get('playbook_reason') or 'N/A'}
Playbook Source: {item.get('playbook_source') or 'N/A'}

INVESTIGATION

Account Verified: {'YES' if item['account_verified'] else 'NO'}
Employee Contacted: {'YES' if item['employee_contacted'] else 'NO'}
Evidence Reviewed: {'YES' if item['evidence_reviewed'] else 'NO'}

ANALYST DECISION

{item['decision']}

ASSIGNED ANALYST

{item.get('assigned_to') or 'Not assigned'}

ANALYST NOTES

{item['notes'] or 'No notes recorded.'}

AUDIT INFORMATION

Created At: {item['created_at']}
Updated At: {item['updated_at']}

==================================================
EDUCATIONAL PROTOTYPE
This report is generated from simulated data.
No real security response actions were performed.
""".strip()


def incidents_csv(items):
    output = io.StringIO()

    columns = [
        "Incident ID",
        "Employee",
        "Login Time",
        "Failed Attempts",
        "Unfamiliar Location",
        "Successful Login",
        "Risk",
        "Classification",
        "Source Type",
        "Source IP",
        "Attack Type",
        "Playbook ID",
        "Decision",
        "Assigned To",
        "Notes",
        "Created At",
        "Updated At"
    ]

    writer = csv.writer(output)
    writer.writerow(columns)

    for item in items:
        writer.writerow([
            incident_number(item["id"]),
            item["employee"],
            item["login_time"],
            item["failed_attempts"],
            item["unfamiliar_location"],
            item["successful_login"],
            item["risk"],
            item["classification"],
            item.get("source_type", ""),
            item.get("source_ip", ""),
            item.get("attack_type", ""),
            item.get("playbook_id", ""),
            item["decision"],
            item.get("assigned_to", ""),
            item["notes"],
            item["created_at"],
            item["updated_at"]
        ])

    return output.getvalue().encode("utf-8-sig")
def pdf_escape(value):
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )

def simple_pdf(text):
    lines = []

    for original_line in str(text).splitlines():
        line = original_line.strip()

        if not line:
            lines.append("")
            continue

        while len(line) > 88:
            split_at = line.rfind(" ", 0, 88)

            if split_at <= 0:
                split_at = 88

            lines.append(line[:split_at])
            line = line[split_at:].strip()

        lines.append(line)

    pages = []

    for start in range(0, len(lines), 45):
        pages.append(lines[start:start + 45])

    if not pages:
        pages = [["CyberShield Enterprise SOC"]]

    objects = []

    objects.append(
        "<< /Type /Catalog /Pages 2 0 R >>"
    )

    page_ids = []

    next_object_id = 3

    for _ in pages:
        page_ids.append(next_object_id)
        next_object_id += 2

    kids = " ".join(
        f"{page_id} 0 R"
        for page_id in page_ids
    )

    objects.append(
        f"<< /Type /Pages /Kids [{kids}] "
        f"/Count {len(page_ids)} >>"
    )

    font_object_id = next_object_id

    for index, page_lines in enumerate(pages):
        page_object_id = page_ids[index]
        stream_object_id = page_object_id + 1

        content = [
            "BT",
            "/F1 9 Tf",
            "45 790 Td",
            "12 TL"
        ]

        first = True

        for line in page_lines:
            escaped = pdf_escape(line)

            if first:
                content.append(
                    f"({escaped}) Tj"
                )
                first = False
            else:
                content.append("T*")
                content.append(
                    f"({escaped}) Tj"
                )

        content.append("ET")

        stream = "\n".join(content)

        page_object = (
            "<< /Type /Page "
            "/Parent 2 0 R "
            "/MediaBox [0 0 595 842] "
            f"/Contents {stream_object_id} 0 R "
            "/Resources << "
            f"/Font << /F1 {font_object_id} 0 R >> "
            ">> >>"
        )

        stream_object = (
            f"<< /Length {len(stream.encode('latin-1', errors='replace'))} >>\n"
            "stream\n"
            f"{stream}\n"
            "endstream"
        )

        objects.append(page_object)
        objects.append(stream_object)

    objects.append(
        "<< /Type /Font "
        "/Subtype /Type1 "
        "/BaseFont /Helvetica >>"
    )

    output = bytearray()
    output.extend(b"%PDF-1.4\n")

    offsets = [0]

    for object_id, object_body in enumerate(
        objects,
        start=1
    ):
        offsets.append(len(output))

        object_text = (
            f"{object_id} 0 obj\n"
            f"{object_body}\n"
            "endobj\n"
        )

        output.extend(
            object_text.encode(
                "latin-1",
                errors="replace"
            )
        )

    xref_position = len(output)

    output.extend(
        (
            f"xref\n0 {len(objects) + 1}\n"
            "0000000000 65535 f \n"
        ).encode("ascii")
    )

    for offset in offsets[1:]:
        output.extend(
            f"{offset:010d} 00000 n \n".encode(
                "ascii"
            )
        )

    output.extend(
        (
            "trailer\n"
            f"<< /Size {len(objects) + 1} "
            "/Root 1 0 R >>\n"
            "startxref\n"
            f"{xref_position}\n"
            "%%EOF"
        ).encode("ascii")
    )

    return bytes(output)

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200000
    ).hex()

    return salt, digest

def verify_password(
    password,
    expected_salt,
    expected_digest
):
    _, calculated = hash_password(
        password,
        expected_salt
    )

    return hmac.compare_digest(
        calculated,
        expected_digest
    )

def configured_accounts():
    admin_password = str(
        get_setting(
            "CYBERSHIELD_ADMIN_PASSWORD",
            "Admin123!"
        )
    )

    analyst_password = str(
        get_setting(
            "CYBERSHIELD_ANALYST_PASSWORD",
            "Analyst123!"
        )
    )

    viewer_password = str(
        get_setting(
            "CYBERSHIELD_VIEWER_PASSWORD",
            "Viewer123!"
        )
    )

    accounts = {}

    for username, password, role in (
        (
            "admin",
            admin_password,
            "Administrator"
        ),
        (
            "analyst",
            analyst_password,
            "Security Analyst"
        ),
        (
            "viewer",
            viewer_password,
            "Viewer"
        )
    ):
        salt = hashlib.sha256(
            f"{APP_NAME}:{username}".encode(
                "utf-8"
            )
        ).hexdigest()[:32]

        _, digest = hash_password(
            password,
            salt
        )

        accounts[username] = {
            "salt": salt,
            "digest": digest,
            "role": role
        }

    return accounts

def authenticate_user(username, password):
    username = username.strip().lower()
    accounts = configured_accounts()
    account = accounts.get(username)

    if not account:
        return None

    if verify_password(
        password,
        account["salt"],
        account["digest"]
    ):
        return {
            "username": username,
            "role": account["role"]
        }

    return None

def role_permissions(role):
    permissions = {
        "Administrator": {
            "dashboard",
            "alerts",
            "raw_logs",
            "incidents",
            "audit",
            "integrations",
            "testing",
            "about",
            "review"
        },
        "Security Analyst": {
            "dashboard",
            "alerts",
            "raw_logs",
            "incidents",
            "audit",
            "testing",
            "about",
            "review"
        },
        "Viewer": {
            "dashboard",
            "incidents",
            "audit",
            "about"
        }
    }

    return permissions.get(
        role,
        set()
    )

def can(permission):
    role = st.session_state.get(
        "role",
        "Viewer"
    )

    return permission in role_permissions(role)

def initialize_session():
    defaults = {
        "authenticated": False,
        "username": "",
        "role": "",
        "active_incident": None,
        "raw_logs": None,
        "raw_alerts": None,
        "raw_filename": "",
        "raw_bytes": None,
        "last_ai_analysis": "",
        "login_error": ""
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

def logout():
    for key in (
        "authenticated",
        "username",
        "role",
        "active_incident",
        "raw_logs",
        "raw_alerts",
        "raw_filename",
        "raw_bytes",
        "last_ai_analysis"
    ):
        if key in st.session_state:
            del st.session_state[key]

    st.rerun()

def extract_openai_text(payload):
    if isinstance(payload, dict):
        output_text = payload.get(
            "output_text"
        )

        if output_text:
            return str(output_text).strip()

        for item in payload.get(
            "output",
            []
        ):
            if not isinstance(item, dict):
                continue

            for content in item.get(
                "content",
                []
            ):
                if not isinstance(
                    content,
                    dict
                ):
                    continue

                if content.get("text"):
                    return str(
                        content["text"]
                    ).strip()

    return ""

def ai_analyze_incident(item):
    api_key = get_setting(
        "OPENAI_API_KEY"
    )

    if not api_key:
        return None, (
            "OPENAI_API_KEY is not configured."
        )

    evidence = item.get(
        "evidence_json",
        "[]"
    )

    prompt = f"""
You are assisting a human cybersecurity analyst
inside an educational SOC prototype.

Analyze the simulated authentication incident below.

Incident ID: {incident_number(item['id'])}
Account: {item['employee']}
Risk: {item['risk']}
Classification: {item['classification']}
Failed attempts: {item['failed_attempts']}
Successful login: {bool(item['successful_login'])}
Unfamiliar location: {bool(item['unfamiliar_location'])}
Source IP: {item.get('source_ip') or 'N/A'}
Attack type: {item.get('attack_type') or 'N/A'}
Evidence: {evidence}

Return a concise analyst-oriented response with:
1. Threat interpretation
2. Important evidence
3. Recommended investigation steps
4. Potential false-positive considerations
5. Final recommendation

Do not claim that containment actions were executed.
Human approval is required.
""".strip()

    body = {
        "model": OPENAI_MODEL,
        "input": prompt
    }

    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(
            body
        ).encode("utf-8"),
        headers={
            "Authorization": (
                f"Bearer {api_key}"
            ),
            "Content-Type": (
                "application/json"
            )
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=45
        ) as response:
            payload = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )

        text = extract_openai_text(
            payload
        )

        if not text:
            return None, (
                "AI response did not contain text."
            )

        with db_connection() as connection:
            append_audit(
                connection,
                item["id"],
                "AI_ANALYSIS_REQUESTED",
                (
                    "AI-assisted incident analysis "
                    "was generated for analyst review."
                )
            )

        return text, None

    except urllib.error.HTTPError as error:
        try:
            detail = error.read().decode(
                "utf-8"
            )
        except Exception:
            detail = str(error)

        return None, (
            f"AI service error: {detail}"
        )

    except Exception as error:
        return None, str(error)

def integration_status():
    return {
        "OpenAI": bool(
            get_setting("OPENAI_API_KEY")
        ),
        "External SIEM": bool(
            get_setting("SIEM_WEBHOOK_URL")
        ),
        "Threat Intelligence": bool(
            get_setting(
                "THREAT_INTELLIGENCE_API_KEY"
            )
        )
    }

def record_integration_event(
    source,
    event_type,
    payload
):
    with db_connection() as connection:
        connection.execute("""
            INSERT INTO integration_events (
                source,
                event_type,
                payload,
                created_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            source,
            event_type,
            json.dumps(
                payload,
                ensure_ascii=False,
                default=str
            ),
            now_text()
        ))

def send_test_webhook():
    webhook_url = get_setting(
        "SIEM_WEBHOOK_URL"
    )

    if not webhook_url:
        return False, (
            "SIEM_WEBHOOK_URL is not configured."
        )

    payload = {
        "source": APP_NAME,
        "event_type": "CONNECTIVITY_TEST",
        "timestamp": now_text(),
        "message": (
            "CyberShield integration test."
        )
    }

    request = urllib.request.Request(
        webhook_url,
        data=json.dumps(
            payload
        ).encode("utf-8"),
        headers={
            "Content-Type": (
                "application/json"
            )
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=15
        ) as response:
            status = response.status

        record_integration_event(
            "External SIEM",
            "CONNECTIVITY_TEST",
            {
                "status": status
            }
        )

        return True, (
            f"Webhook returned HTTP {status}."
        )

    except Exception as error:
        return False, str(error)

def run_self_tests():
    results = []

    try:
        with db_connection() as connection:
            connection.execute(
                "SELECT 1"
            ).fetchone()

        results.append({
            "Test": "Database connection",
            "Status": "PASS",
            "Details": "SQLite database is accessible."
        })
    except Exception as error:
        results.append({
            "Test": "Database connection",
            "Status": "FAIL",
            "Details": str(error)
        })

    try:
        sample_logs = [
            {
                "timestamp": "2026-11-09 10:00:00",
                "username": "test_user",
                "source_ip": "198.51.100.10",
                "location": "Test",
                "status": "failed"
            },
            {
                "timestamp": "2026-11-09 10:01:00",
                "username": "test_user",
                "source_ip": "198.51.100.10",
                "location": "Test",
                "status": "failed"
            },
            {
                "timestamp": "2026-11-09 10:02:00",
                "username": "test_user",
                "source_ip": "198.51.100.10",
                "location": "Test",
                "status": "failed"
            },
            {
                "timestamp": "2026-11-09 10:03:00",
                "username": "test_user",
                "source_ip": "198.51.100.10",
                "location": "Test",
                "status": "failed"
            },
            {
                "timestamp": "2026-11-09 10:04:00",
                "username": "test_user",
                "source_ip": "198.51.100.10",
                "location": "Test",
                "status": "failed"
            }
        ]

        detected = (
            detect_authentication_threats(
                sample_logs
            )
        )

        brute_force = any(
            item["attack"] == "Brute Force"
            for item in detected
        )

        results.append({
            "Test": "Brute-force detection",
            "Status": (
                "PASS"
                if brute_force
                else "FAIL"
            ),
            "Details": (
                "Brute-force rule detected "
                "five failed attempts."
            )
        })

    except Exception as error:
        results.append({
            "Test": "Brute-force detection",
            "Status": "FAIL",
            "Details": str(error)
        })

    try:
        spraying_logs = [
            {
                "timestamp": "2026-11-09 11:00:00",
                "username": "user1",
                "source_ip": "203.0.113.5",
                "location": "Test",
                "status": "failed"
            },
            {
                "timestamp": "2026-11-09 11:01:00",
                "username": "user2",
                "source_ip": "203.0.113.5",
                "location": "Test",
                "status": "failed"
            },
            {
                "timestamp": "2026-11-09 11:02:00",
                "username": "user3",
                "source_ip": "203.0.113.5",
                "location": "Test",
                "status": "failed"
            }
        ]

        detected = (
            detect_authentication_threats(
                spraying_logs
            )
        )

        spraying = any(
            item["attack"]
            == "Password Spraying"
            for item in detected
        )

        results.append({
            "Test": "Password spraying detection",
            "Status": (
                "PASS"
                if spraying
                else "FAIL"
            ),
            "Details": (
                "Password-spraying rule "
                "evaluated successfully."
            )
        })

    except Exception as error:
        results.append({
            "Test": "Password spraying detection",
            "Status": "FAIL",
            "Details": str(error)
        })

    try:
        audit_result = verify_audit_chain()

        results.append({
            "Test": "Audit integrity",
            "Status": (
                "PASS"
                if audit_result["valid"]
                else "FAIL"
            ),
            "Details": audit_result["message"]
        })

    except Exception as error:
        results.append({
            "Test": "Audit integrity",
            "Status": "FAIL",
            "Details": str(error)
        })

    try:
        report_test = simple_pdf(
            "CyberShield PDF Test"
        )

        pdf_valid = (
            report_test.startswith(
                b"%PDF"
            )
        )

        results.append({
            "Test": "PDF generation",
            "Status": (
                "PASS"
                if pdf_valid
                else "FAIL"
            ),
            "Details": (
                "PDF report generator is available."
            )
        })

    except Exception as error:
        results.append({
            "Test": "PDF generation",
            "Status": "FAIL",
            "Details": str(error)
        })

    return results

def section(title, description=""):
    st.subheader(title)

    if description:
        st.caption(description)

def show_playbook(item):
    playbook = get_playbook(
        item["risk"]
    )

    section(
        "Recommended Response Playbook",
        "Human-controlled response guidance."
    )

    if not playbook:
        st.warning(
            "No playbook is mapped to this risk."
        )
        return

    a, b = st.columns(2)

    a.metric(
        "Playbook",
        playbook["id"]
    )

    b.metric(
        "Risk",
        item["risk"]
    )

    st.caption(
        playbook["source"]
    )

    st.info(
        playbook["reason"]
    )

    for index, step in enumerate(
        playbook["steps"],
        start=1
    ):
        st.markdown(
            f"**{index:02d}. {step}**"
        )

def show_incident_details(item):
    section(
        "Incident Summary"
    )

    a, b, c, d = st.columns(4)

    a.metric(
        "Incident ID",
        incident_number(item["id"])
    )

    b.metric(
        "Account",
        item["employee"]
    )

    c.metric(
        "Risk",
        item["risk"]
    )

    d.metric(
        "Failed Attempts",
        item["failed_attempts"]
    )

    e, f, g, h = st.columns(4)

    e.metric(
        "Source",
        item.get(
            "source_type",
            "Manual Alert"
        )
    )

    f.metric(
        "Source IP",
        item.get(
            "source_ip"
        ) or "N/A"
    )

    g.metric(
        "Successful Login",
        (
            "YES"
            if item["successful_login"]
            else "NO"
        )
    )

    h.metric(
        "Unfamiliar Location",
        (
            "YES"
            if item["unfamiliar_location"]
            else "NO"
        )
    )

    st.markdown(
        f"### {escape(item['classification'])}"
    )

    if item["risk"] == "HIGH":
        st.error(
            item["explanation"]
        )

    elif item["risk"] == "LOW":
        st.success(
            item["explanation"]
        )

    else:
        st.warning(
            item["explanation"]
        )

    show_playbook(item)

def show_analyst_workspace(item):
    st.divider()

    section(
        "Security Analyst Workspace",
        (
            "Review evidence and record "
            "the human analyst decision."
        )
    )

    with st.form(
        f"review_form_{item['id']}"
    ):
        verified = st.checkbox(
            "Employee account and identity verified",
            value=bool(
                item["account_verified"]
            )
        )

        contacted = st.checkbox(
            "Employee contacted through approved channel",
            value=bool(
                item["employee_contacted"]
            )
        )

        reviewed = st.checkbox(
            "Authentication evidence reviewed",
            value=bool(
                item["evidence_reviewed"]
            )
        )

        assigned_to = st.text_input(
            "Assigned Analyst",
            value=(
                item.get(
                    "assigned_to"
                )
                or st.session_state.username
            )
        )


        notes = st.text_area(
            "Investigation Notes",
            value=item["notes"],
            height=140
        )

        decisions = [
            "Pending Review",
            "Approve",
            "Reject"
        ]

        decision = st.radio(
            "Analyst Decision",
            decisions,
            index=(
                decisions.index(
                    item["decision"]
                )
                if item["decision"]
                in decisions
                else 0
            ),
            horizontal=True
        )

        save_review = (
            st.form_submit_button(
                "Save Analyst Review",
                type="primary",
                use_container_width=True
            )
        )

    if save_review:
        update_review(
            item["id"],
            decision,
            notes,
            verified,
            contacted,
            reviewed,
            assigned_to
        )

        st.success(
            "Analyst review saved."
        )

        st.rerun()

    completed = sum([
        bool(item["account_verified"]),
        bool(item["employee_contacted"]),
        bool(item["evidence_reviewed"])
    ])

    st.progress(
        completed / 3
    )

    st.caption(
        f"{completed} of 3 investigation "
        "checks completed."
    )

    report_text = incident_report(
        item
    )

    report_pdf = simple_pdf(
        report_text
    )

    col1, col2 = st.columns(2)

    col1.download_button(
        "Download TXT Report",
        data=report_text.encode(
            "utf-8"
        ),
        file_name=(
            f"{incident_number(item['id'])}"
            "_report.txt"
        ),
        mime="text/plain",
        use_container_width=True
    )

    col2.download_button(
        "Download PDF Report",
        data=report_pdf,
        file_name=(
            f"{incident_number(item['id'])}"
            "_report.pdf"
        ),
        mime="application/pdf",
        use_container_width=True
    )

    st.divider()

    section(
        "AI-Assisted Analysis",
        (
            "Optional AI assistance for "
            "human analyst review."
        )
    )

    if not get_setting(
        "OPENAI_API_KEY"
    ):
        st.info(
            "AI analysis is available when "
            "OPENAI_API_KEY is configured."
        )

    if st.button(
        "Run AI Incident Analysis",
        key=f"ai_{item['id']}",
        disabled=not bool(
            get_setting(
                "OPENAI_API_KEY"
            )
        )
    ):
        with st.spinner(
            "Analyzing incident..."
        ):
            analysis, error = (
                ai_analyze_incident(
                    item
                )
            )

        if error:
            st.error(error)
        else:
            st.session_state[
                "last_ai_analysis"
            ] = analysis

    if st.session_state.get(
        "last_ai_analysis"
    ):
        st.markdown(
            st.session_state[
                "last_ai_analysis"
            ]
        )

def render_dashboard():
    items = load_incidents()
    metrics = load_security_metrics()

    section(
        "Security Command Center",
        (
            "Operational overview of "
            "simulated SOC activity."
        )
    )

    a, b, c, d = st.columns(4)

    a.metric(
        "Total Incidents",
        metrics["total"]
    )

    b.metric(
        "High Risk",
        metrics["high"]
    )

    c.metric(
        "Pending Review",
        metrics["pending"]
    )

    d.metric(
        "Approved",
        metrics["approved"]
    )

    if not items:
        st.info(
            "No incidents recorded."
        )
        return

    st.divider()

    left, right = st.columns(2)

    with left:
        section(
            "Risk Distribution"
        )

        risk_data = {
            "HIGH": metrics["high"],
            "LOW": metrics["low"],
            "UNCLEAR": metrics["unclear"]
        }

        st.bar_chart(
            risk_data
        )

    with right:
        section(
            "Decision Distribution"
        )

        decision_data = {
            "Approved": metrics["approved"],
            "Rejected": metrics["rejected"],
            "Pending": metrics["pending"]
        }

        st.bar_chart(
            decision_data
        )

    st.divider()

    section(
        "Incident Timeline"
    )

    daily_counts = Counter()

    for item in items:
        try:
            day = item[
                "created_at"
            ][:10]

            daily_counts[day] += 1
        except Exception:
            continue

    if daily_counts:
        timeline = [
            {
                "Date": day,
                "Incidents": count
            }
            for day, count
            in sorted(
                daily_counts.items()
            )
        ]

        st.line_chart(
            {
                row["Date"]:
                    row["Incidents"]
                for row in timeline
            }
        )

        st.dataframe(
            timeline,
            use_container_width=True,
            hide_index=True
        )

    st.divider()

    section(
        "Recent Incidents"
    )

    recent = [
        {
            "Incident ID":
                incident_number(
                    item["id"]
                ),
            "Employee":
                item["employee"],
            "Risk":
                item["risk"],
            "Classification":
                item["classification"],
            "Decision":
                item["decision"],
            "Source":
                item.get(
                    "source_type",
                    ""
                ),
            "Created At":
                item["created_at"]
        }
        for item in items[:10]
    ]

    st.dataframe(
        recent,
        use_container_width=True,
        hide_index=True
    )

def render_alert_analysis():
    section(
        "Security Alert Analysis",
        (
            "Analyze a simulated "
            "authentication alert."
        )
    )

    scenario = st.selectbox(
        "Quick Test Scenario",
        [
            "Custom Alert",
            "High Risk Example",
            "Low Risk Example",
            "Unclear Risk Example"
        ]
    )

    samples = {
        "Custom Alert": (
            "employee01",
            0,
            False,
            False
        ),
        "High Risk Example": (
            "employee_high",
            5,
            True,
            True
        ),
        "Low Risk Example": (
            "employee_low",
            0,
            False,
            True
        ),
        "Unclear Risk Example": (
            "employee_review",
            2,
            True,
            False
        )
    }

    (
        employee_default,
        attempts_default,
        unfamiliar_default,
        success_default
    ) = samples[scenario]

    with st.form(
        f"alert_form_{scenario}"
    ):
        a, b = st.columns(2)

        with a:
            employee = st.text_input(
                "Employee Account",
                value=employee_default
            )

            login_time = st.time_input(
                "Login Time",
                value=time(9, 0)
            )

        with b:
            attempts = st.number_input(
                "Failed Login Attempts",
                min_value=0,
                max_value=1000,
                value=attempts_default,
                step=1
            )

            unfamiliar = st.checkbox(
                "Unfamiliar Location",
                value=unfamiliar_default
            )

            successful = st.checkbox(
                "Successful Login",
                value=success_default
            )

        analyze = (
            st.form_submit_button(
                "Analyze and Create Incident",
                type="primary",
                use_container_width=True
            )
        )

    if analyze:
        if not employee.strip():
            st.error(
                "Employee account is required."
            )
        else:
            incident_id = create_incident(
                employee=employee.strip(),
                login_time=login_time,
                attempts=int(attempts),
                unfamiliar=unfamiliar,
                successful=successful
            )

            st.session_state[
                "active_incident"
            ] = incident_id

            st.rerun()

    if st.session_state.get(
        "active_incident"
    ):
        item = load_incident(
            st.session_state[
                "active_incident"
            ]
        )

        if item:
            st.success(
                f"{incident_number(item['id'])} "
                "created successfully."
            )

            show_incident_details(
                item
            )

            if can("review"):
                show_analyst_workspace(
                    item
                )

def render_raw_log_analysis():
    section(
        "Raw Authentication Log Analysis",
        (
            "Upload simulated authentication "
            "logs and detect attack patterns."
        )
    )

    uploaded_file = st.file_uploader(
        "Choose Authentication Log CSV",
        type=["csv"]
    )

    if uploaded_file is not None:
        raw_bytes = (
            uploaded_file.getvalue()
        )

        try:
            logs = (
                validate_authentication_logs(
                    raw_bytes
                )
            )

            st.session_state[
                "raw_logs"
            ] = logs

            st.session_state[
                "raw_filename"
            ] = uploaded_file.name

            st.session_state[
                "raw_bytes"
            ] = raw_bytes

            st.success(
                f"Validated {len(logs)} "
                "authentication events."
            )

            st.dataframe(
                logs,
                use_container_width=True,
                hide_index=True
            )

        except Exception as error:
            st.error(
                str(error)
            )

            st.session_state[
                "raw_logs"
            ] = None

    logs = st.session_state.get(
        "raw_logs"
    )

    if logs:
        if st.button(
            "Detect Security Threats",
            type="primary",
            use_container_width=True
        ):
            alerts = (
                detect_authentication_threats(
                    logs
                )
            )

            st.session_state[
                "raw_alerts"
            ] = alerts

            batch_id, created = (
                save_log_batch(
                    st.session_state[
                        "raw_filename"
                    ],
                    st.session_state[
                        "raw_bytes"
                    ],
                    logs,
                    alerts,
                    st.session_state[
                        "username"
                    ]
                )
            )

            if created:
                st.success(
                    f"Log batch {batch_id} "
                    "stored successfully."
                )
            else:
                st.info(
                    f"Log batch {batch_id} "
                    "already exists."
                )

    alerts = st.session_state.get(
        "raw_alerts"
    )

    if alerts is not None:
        st.divider()

        section(
            "Detection Results"
        )

        if not alerts:
            st.success(
                "No suspicious patterns "
                "were detected."
            )

        else:
            display_alerts = []

            for alert in alerts:
                display_alerts.append({
                    "Attack":
                        alert["attack"],
                    "Username":
                        alert["username"],
                    "Source IP":
                        alert["source_ip"],
                    "Risk":
                        alert["risk"],
                    "Failed Attempts":
                        alert[
                            "failed_attempts"
                        ],
                    "Timestamp":
                        alert["timestamp"],
                    "Reason":
                        alert["reason"]
                })

            st.error(
                f"Detected {len(alerts)} "
                "potential security threats."
            )

            st.dataframe(
                display_alerts,
                use_container_width=True,
                hide_index=True
            )

            if st.button(
                "Create Incidents From Detected Threats",
                use_container_width=True
            ):
                created_ids = (
                    create_incidents_from_alerts(
                        alerts
                    )
                )

                st.session_state[
                    "raw_alerts"
                ] = []

                st.success(
                    f"Created {len(created_ids)} "
                    "security incidents."
                )

def render_incident_management():
    section(
        "Incident Management",
        (
            "Search, investigate, review, "
            "and export incidents."
        )
    )

    items = load_incidents()

    if not items:
        st.info(
            "No incidents recorded."
        )
        return

    a, b, c = st.columns(
        [2, 1, 1]
    )

    with a:
        search = st.text_input(
            "Search Incidents"
        )

    with b:
        risk_filter = st.selectbox(
            "Risk",
            [
                "ALL",
                "HIGH",
                "LOW",
                "UNCLEAR"
            ]
        )

    with c:
        decision_filter = st.selectbox(
            "Decision",
            [
                "ALL",
                "Pending Review",
                "Approve",
                "Reject"
            ]
        )

    filtered = []

    for item in items:
        searchable = (
            f"{incident_number(item['id'])} "
            f"{item['employee']} "
            f"{item['classification']} "
            f"{item.get('source_ip', '')}"
        ).lower()

        if (
            search
            and search.lower()
            not in searchable
        ):
            continue

        if (
            risk_filter != "ALL"
            and item["risk"]
            != risk_filter
        ):
            continue

        if (
            decision_filter != "ALL"
            and item["decision"]
            != decision_filter
        ):
            continue

        filtered.append(item)

    rows = [
        {
            "Incident ID":
                incident_number(
                    item["id"]
                ),
            "Employee":
                item["employee"],
            "Risk":
                item["risk"],
            "Classification":
                item["classification"],
            "Attack Type":
                item.get(
                    "attack_type",
                    ""
                ),
            "Source IP":
                item.get(
                    "source_ip",
                    ""
                ),
            "Decision":
                item["decision"],
            "Created At":
                item["created_at"]
        }
        for item in filtered
    ]

    st.dataframe(
        rows,
        use_container_width=True,
        hide_index=True
    )

    st.download_button(
        "Export Filtered Incidents CSV",
        data=incidents_csv(filtered),
        file_name=(
            "cybershield_incidents.csv"
        ),
        mime="text/csv"
    )

    if not filtered:
        return

    selected_id = st.selectbox(
        "Open Incident",
        [
            item["id"]
            for item in filtered
        ],
        format_func=lambda value: (
            f"{incident_number(value)} — "
            + next(
                item["employee"]
                for item in filtered
                if item["id"] == value
            )
        )
    )

    selected = load_incident(
        selected_id
    )

    if selected:
        show_incident_details(
            selected
        )

        if can("review"):
            show_analyst_workspace(
                selected
            )

def render_audit_trail():
    section(
        "Security Audit Trail",
        (
            "Review recorded SOC activity "
            "and integrity status."
        )
    )

    verification = (
        verify_audit_chain()
    )

    if verification["valid"]:
        st.success(
            verification["message"]
        )
    else:
        st.error(
            verification["message"]
        )

    st.caption(
        f"Checked records: "
        f"{verification['checked']} | "
        f"Legacy unhashed records: "
        f"{verification['legacy']}"
    )

    events = load_audit_events()

    if not events:
        st.info(
            "No audit events recorded."
        )
        return

    rows = [
        {
            "Event ID":
                event["id"],
            "Incident ID":
                (
                    incident_number(
                        event["incident_id"]
                    )
                    if event[
                        "incident_id"
                    ] is not None
                    else "N/A"
                ),
            "Event Type":
                event["event_type"],
            "Description":
                event["description"],
            "Timestamp":
                event["created_at"],
            "Hash":
                (
                    event.get(
                        "event_hash"
                    ) or ""
                )[:16]
        }
        for event in events
    ]

    st.dataframe(
        rows,
        use_container_width=True,
        hide_index=True
    )

    output = io.StringIO()

    writer = csv.DictWriter(
        output,
        fieldnames=list(
            rows[0].keys()
        )
    )

    writer.writeheader()
    writer.writerows(rows)

    st.download_button(
        "Export Audit Trail CSV",
        data=output.getvalue().encode(
            "utf-8-sig"
        ),
        file_name=(
            "cybershield_audit.csv"
        ),
        mime="text/csv"
    )

def render_integrations():
    section(
        "Security Integrations",
        (
            "Optional external services "
            "for the educational prototype."
        )
    )

    statuses = integration_status()

    rows = [
        {
            "Integration": name,
            "Status": (
                "Configured"
                if configured
                else "Not Configured"
            )
        }
        for name, configured
        in statuses.items()
    ]

    st.dataframe(
        rows,
        use_container_width=True,
        hide_index=True
    )

    if statuses["External SIEM"]:
        if st.button(
            "Test External SIEM Webhook"
        ):
            success, message = (
                send_test_webhook()
            )

            if success:
                st.success(
                    message
                )
            else:
                st.error(
                    message
                )

    st.info(
        "External integrations remain "
        "optional. The prototype does "
        "not require live security systems "
        "to demonstrate its workflow."
    )

def render_testing():
    section(
        "Security Self-Tests",
        (
            "Validate core prototype "
            "functions before demonstration."
        )
    )

    if st.button(
        "Run All Tests",
        type="primary"
    ):
        results = run_self_tests()

        st.session_state[
            "test_results"
        ] = results

    results = st.session_state.get(
        "test_results"
    )

    if results:
        st.dataframe(
            results,
            use_container_width=True,
            hide_index=True
        )

        passed = sum(
            row["Status"] == "PASS"
            for row in results
        )

        total = len(results)

        st.metric(
            "Tests Passed",
            f"{passed}/{total}"
        )

        if passed == total:
            st.success(
                "All available self-tests passed."
            )
        else:
            st.warning(
                "One or more tests require review."
            )

def render_about():
    section(
        "About CyberShield Enterprise SOC"
    )

    st.markdown("""
CyberShield Enterprise SOC is an educational
security operations prototype designed for
simulated authentication incident analysis.

### Capabilities

- Authentication alert analysis
- Raw authentication log ingestion
- Brute-force detection
- Password-spraying detection
- Possible account-compromise detection
- Rule-based risk classification
- Response playbook recommendations
- Human analyst review
- Incident management
- Incident timeline and dashboards
- CSV incident export
- TXT and PDF incident reports
- Hash-linked audit events
- Optional AI-assisted analysis
- Role-based workspace permissions
- Optional external security integrations
- Built-in self-testing

### Human Control

The system provides recommendations and analysis.
It does not automatically disable accounts,
reset passwords, block IP addresses, or perform
other real containment actions.

### Environment

This application is an educational prototype.
Authentication data, attack events, users, and
security actions used for demonstration should
remain fictional or simulated.
""")

def show_login():
    st.markdown(
        """
<style>
[data-testid="stSidebar"] {
    display: none !important;
}

[data-testid="collapsedControl"] {
    display: none !important;
}

[data-testid="stHeader"] {
    background: transparent !important;
}

.block-container {
    max-width: 1450px !important;
    padding-top: 1.4rem !important;
    padding-bottom: 1rem !important;
}

.stApp {
    min-height: 100vh;
    background:
        radial-gradient(
            circle at 76% 45%,
            rgba(35, 128, 185, 0.10),
            transparent 30%
        ),
        radial-gradient(
            circle at 14% 20%,
            rgba(0, 201, 235, 0.07),
            transparent 26%
        ),
        linear-gradient(
            rgba(18, 53, 79, 0.11) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(18, 53, 79, 0.11) 1px,
            transparent 1px
        ),
        #050b13 !important;
    background-size:
        auto,
        auto,
        42px 42px,
        42px 42px,
        auto !important;
}

.login-brand {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 26px;
    margin-top: 8px;
}

.login-logo {
    width: 52px;
    height: 52px;
    border-radius: 14px;
    border: 1px solid rgba(73, 225, 250, 0.65);
    background:
        linear-gradient(
            145deg,
            rgba(17, 42, 59, 0.95),
            rgba(7, 18, 29, 0.95)
        );
    display: flex;
    align-items: center;
    justify-content: center;
    color: #53e5ff;
    font-size: 25px;
    box-shadow:
        0 0 22px rgba(64, 220, 245, 0.18),
        inset 0 0 15px rgba(56, 206, 234, 0.06);
}

.brand-name {
    color: #ffffff;
    font-size: 27px;
    font-weight: 850;
    letter-spacing: 0.5px;
    line-height: 1;
}

.brand-name span {
    color: #45dff4;
}

.brand-sub {
    color: #53cde0;
    font-size: 8px;
    letter-spacing: 4.2px;
    margin-top: 7px;
    font-weight: 600;
}

.login-heading {
    color: #ffffff;
    font-size: 25px;
    font-weight: 820;
    margin-bottom: 5px;
}

.login-description {
    color: #8496aa;
    font-size: 13px;
    margin-bottom: 18px;
}

.right-section {
    min-height: 560px;
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
}

.radar-circle {
    width: 430px;
    height: 430px;
    position: absolute;
    top: 15px;
    left: 50%;
    transform: translateX(-50%);
    border-radius: 50%;
    border: 1px solid rgba(52, 106, 145, 0.18);
    pointer-events: none;
}

.radar-circle:before {
    content: "";
    position: absolute;
    width: 315px;
    height: 315px;
    top: 57px;
    left: 57px;
    border-radius: 50%;
    border: 1px solid rgba(52, 106, 145, 0.14);
}

.radar-circle:after {
    content: "";
    position: absolute;
    width: 195px;
    height: 195px;
    top: 117px;
    left: 117px;
    border-radius: 50%;
    border: 1px solid rgba(52, 106, 145, 0.12);
}

.right-content {
    position: relative;
    z-index: 2;
    text-align: center;
    padding: 15px 30px;
}

.hero-shield {
    width: 86px;
    height: 86px;
    margin: 0 auto 27px auto;
    border-radius: 19px;
    border: 1px solid rgba(70, 104, 139, .60);
    background:
        linear-gradient(
            145deg,
            rgba(25, 42, 65, .96),
            rgba(25, 20, 48, .97)
        );
    display: flex;
    align-items: center;
    justify-content: center;
    color: #4de4fa;
    font-size: 41px;
    box-shadow:
        0 0 30px rgba(45, 209, 239, .11),
        inset 0 0 20px rgba(63, 211, 240, .04);
}

.hero-title-login {
    font-size: 28px;
    line-height: 1.3;
    font-weight: 850;
    color: #ffffff;
    margin-bottom: 12px;
}

.hero-text-login {
    color: #8fa1b4;
    font-size: 13px;
    line-height: 1.7;
    max-width: 520px;
    margin: 0 auto 25px auto;
}

.stats-grid-login {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    max-width: 440px;
    margin: 0 auto;
}

.stat-card-login {
    background:
        linear-gradient(
            145deg,
            rgba(17, 27, 42, .94),
            rgba(12, 18, 31, .96)
        );
    border: 1px solid rgba(57, 75, 99, .70);
    border-radius: 12px;
    padding: 18px 13px;
    min-height: 87px;
    box-shadow:
        inset 0 1px 0 rgba(255,255,255,.018);
}

.stat-icon-login {
    color: #48dcf4;
    font-size: 18px;
    margin-bottom: 4px;
}

.stat-value-login {
    color: #ffffff;
    font-weight: 850;
    font-size: 20px;
}

.stat-label-login {
    color: #60748a;
    font-size: 9px;
    letter-spacing: .8px;
    margin-top: 4px;
}

.tags-login {
    max-width: 520px;
    margin: 18px auto 0 auto;
    text-align: center;
}

.tag-login {
    display: inline-block;
    color: #9eb1c3;
    background: rgba(11, 19, 31, .80);
    border: 1px solid rgba(54, 74, 96, .70);
    border-radius: 20px;
    font-size: 10px;
    padding: 5px 11px;
    margin: 3px;
}

.demo-divider {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 16px 0 10px 0;
}

.demo-divider-line {
    flex: 1;
    height: 1px;
    background: #29394b;
}

.demo-divider-text {
    color: #52677d;
    font-size: 9px;
    letter-spacing: 1px;
}

.footer-login {
    color: #435367;
    font-size: 9px;
    text-align: center;
    margin-top: 25px;
}

.stTextInput label {
    color: #a8b7c7 !important;
    font-size: 10px !important;
    font-weight: 750 !important;
    letter-spacing: 1px !important;
}

.stTextInput input {
    height: 45px !important;
    background: #172231 !important;
    border: 1px solid #34465a !important;
    color: white !important;
    border-radius: 9px !important;
}

.stTextInput input:focus {
    border-color: #40d8ef !important;
    box-shadow:
        0 0 0 1px rgba(64,216,239,.2) !important;
}

[data-testid="stForm"] {
    background:
        linear-gradient(
            160deg,
            rgba(19, 31, 45, 0.97),
            rgba(11, 20, 32, 0.98)
        ) !important;
    border: 1px solid rgba(70, 91, 112, 0.62) !important;
    border-radius: 17px !important;
    padding: 24px !important;
    box-shadow:
        0 28px 65px rgba(0, 0, 0, 0.42),
        inset 0 1px 0 rgba(255,255,255,.025) !important;
}

.stFormSubmitButton > button {
    width: 100% !important;
    height: 44px !important;
    background:
        linear-gradient(
            90deg,
            #3cc7e2,
            #55dcf3
        ) !important;
    color: #06121c !important;
    border: none !important;
    font-weight: 850 !important;
    border-radius: 8px !important;
    box-shadow:
        0 8px 22px rgba(59, 207, 233, .17) !important;
}

.stButton > button {
    height: 42px !important;
    background: #172131 !important;
    color: #dbe7f2 !important;
    border: 1px solid #314257 !important;
    border-radius: 8px !important;
    font-size: 11px !important;
    font-weight: 700 !important;
}

.stButton > button:hover {
    border-color: #46d8ee !important;
    color: #52e1f6 !important;
}

@media (max-width: 950px) {
    .radar-circle {
        display: none;
    }

    .right-section {
        min-height: auto;
    }

    .hero-title-login {
        font-size: 23px;
    }
}
</style>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
<div class="login-brand">
    <div class="login-logo">♢</div>
    <div>
        <div class="brand-name">
            CYBERSHIELD <span>IQ</span>
        </div>
        <div class="brand-sub">
            ENTERPRISE SECURITY OPERATIONS
        </div>
    </div>
</div>
        """,
        unsafe_allow_html=True
    )

    left, right = st.columns(
        [0.86, 1.42],
        gap="large"
    )

    with left:
        st.markdown(
            """
<div class="login-heading">Welcome Back</div>
<div class="login-description">
    Sign in to your security operations account
</div>
            """,
            unsafe_allow_html=True
        )

        with st.form("login_form"):
            username = st.text_input(
                "USERNAME",
                placeholder="Username"
            )

            password = st.text_input(
                "PASSWORD",
                type="password",
                placeholder="••••••••••••"
            )

            login = st.form_submit_button(
                "Sign In   →",
                type="primary",
                use_container_width=True
            )

        st.markdown(
            """
<div class="demo-divider">
    <div class="demo-divider-line"></div>
    <div class="demo-divider-text">DEMO ACCOUNTS</div>
    <div class="demo-divider-line"></div>
</div>
            """,
            unsafe_allow_html=True
        )

        a, b = st.columns(2)

        with a:
            admin_demo = st.button(
                "👑  Administrator",
                use_container_width=True,
                key="administrator_demo"
            )

        with b:
            analyst_demo = st.button(
                "🛡  SOC Analyst",
                use_container_width=True,
                key="analyst_demo"
            )

        c, d = st.columns(2)

        with c:
            viewer_demo = st.button(
                "▣  Viewer",
                use_container_width=True,
                key="viewer_demo"
            )

        with d:
            st.button(
                "◉  Security SOC",
                use_container_width=True,
                disabled=True,
                key="soc_status"
            )

        if login:
            user = authenticate_user(
                username,
                password
            )

            if user:
                st.session_state.authenticated = True
                st.session_state.username = user["username"]
                st.session_state.role = user["role"]

                with db_connection() as connection:
                    append_audit(
                        connection,
                        None,
                        "USER_LOGIN",
                        (
                            f"{user['username']} signed in "
                            f"as {user['role']}."
                        )
                    )

                st.rerun()
            else:
                st.error(
                    "Invalid username or password."
                )

        if admin_demo:
            st.session_state.authenticated = True
            st.session_state.username = "admin"
            st.session_state.role = "Administrator"

            with db_connection() as connection:
                append_audit(
                    connection,
                    None,
                    "USER_LOGIN",
                    "admin signed in as Administrator."
                )

            st.rerun()

        if analyst_demo:
            st.session_state.authenticated = True
            st.session_state.username = "analyst"
            st.session_state.role = "Security Analyst"

            with db_connection() as connection:
                append_audit(
                    connection,
                    None,
                    "USER_LOGIN",
                    (
                        "analyst signed in as "
                        "Security Analyst."
                    )
                )

            st.rerun()

        if viewer_demo:
            st.session_state.authenticated = True
            st.session_state.username = "viewer"
            st.session_state.role = "Viewer"

            with db_connection() as connection:
                append_audit(
                    connection,
                    None,
                    "USER_LOGIN",
                    "viewer signed in as Viewer."
                )

            st.rerun()

    with right:
        st.markdown(
            """
<div class="right-section">
    <div class="radar-circle"></div>
    <div class="right-content">
        <div class="hero-shield">♢</div>
        <div class="hero-title-login">
            Next-Gen Cyber Security<br>
            Operations & Risk Management
        </div>
        <div class="hero-text-login">
            Detect suspicious authentication behavior,
            analyze raw security logs, investigate incidents,
            assess risk, and support human-controlled
            response decisions from one unified SOC platform.
        </div>
        <div class="stats-grid-login">
            <div class="stat-card-login">
                <div class="stat-icon-login">♢</div>
                <div class="stat-value-login">24/7</div>
                <div class="stat-label-login">
                    SECURITY MONITORING
                </div>
            </div>
            <div class="stat-card-login">
                <div class="stat-icon-login">♙</div>
                <div class="stat-value-login">3</div>
                <div class="stat-label-login">
                    ACCESS ROLES
                </div>
            </div>
            <div class="stat-card-login">
                <div class="stat-icon-login">◎</div>
                <div class="stat-value-login">AI</div>
                <div class="stat-label-login">
                    INCIDENT ANALYSIS
                </div>
            </div>
            <div class="stat-card-login">
                <div class="stat-icon-login">◉</div>
                <div class="stat-value-login">SOC</div>
                <div class="stat-label-login">
                    RESPONSE PLATFORM
                </div>
            </div>
        </div>
        <div class="tags-login">
            <span class="tag-login">✓ Threat Detection</span>
            <span class="tag-login">✓ Raw Log Analysis</span>
            <span class="tag-login">✓ Incident Response</span>
            <span class="tag-login">✓ Risk Scoring</span>
            <span class="tag-login">✓ Audit Protection</span>
            <span class="tag-login">✓ AI Assistance</span>
            <span class="tag-login">✓ Role-Based Access</span>
        </div>
    </div>
</div>
            """,
            unsafe_allow_html=True
        )

    st.markdown(
        """
<div class="footer-login">
    © 2026 CyberShield Solutions · Group 13 · Project 20
</div>
        """,
        unsafe_allow_html=True
    )


initialize_database()
initialize_session()

st.markdown("""
<style>
:root {
    --cs-bg: #050b13;
    --cs-panel: #0c1624;
    --cs-panel-2: #101d2d;
    --cs-border: rgba(77, 112, 145, 0.38);
    --cs-border-soft: rgba(77, 112, 145, 0.22);
    --cs-text: #f5f9ff;
    --cs-muted: #8295aa;
    --cs-cyan: #4de4fa;
    --cs-cyan-2: #2fc6df;
    --cs-red: #ff6474;
    --cs-green: #57d8a4;
}

.stApp {
    min-height: 100vh;
    background:
        radial-gradient(circle at 78% 8%, rgba(47, 198, 223, .08), transparent 26%),
        radial-gradient(circle at 18% 30%, rgba(48, 116, 180, .07), transparent 24%),
        linear-gradient(rgba(25, 59, 86, .08) 1px, transparent 1px),
        linear-gradient(90deg, rgba(25, 59, 86, .08) 1px, transparent 1px),
        var(--cs-bg) !important;
    background-size: auto, auto, 42px 42px, 42px 42px, auto !important;
    color: var(--cs-text);
}

[data-testid="stHeader"] {
    background: rgba(5, 11, 19, .76) !important;
    backdrop-filter: blur(14px);
    border-bottom: 1px solid rgba(67, 93, 118, .18);
}

[data-testid="stSidebar"] {
    background:
        radial-gradient(circle at 20% 0%, rgba(53, 208, 235, .08), transparent 28%),
        linear-gradient(180deg, #09131f 0%, #07101a 100%) !important;
    border-right: 1px solid rgba(70, 103, 133, .34) !important;
}

[data-testid="stSidebar"] > div:first-child {
    padding-top: 1.25rem;
}

.block-container {
    max-width: 1540px !important;
    padding-top: 1.45rem !important;
    padding-bottom: 3rem !important;
}

h1, h2, h3, h4 {
    color: var(--cs-text) !important;
    letter-spacing: -.25px;
}

p, label, .stCaption {
    color: #9fb0c2;
}

hr {
    border-color: rgba(75, 103, 129, .28) !important;
}

.cs-sidebar-brand {
    display: flex;
    align-items: center;
    gap: 11px;
    padding: 4px 2px 12px 2px;
}

.cs-sidebar-logo {
    width: 39px;
    height: 39px;
    border: 1px solid rgba(77, 228, 250, .55);
    border-radius: 11px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--cs-cyan);
    font-size: 19px;
    background: linear-gradient(145deg, rgba(21, 40, 56, .94), rgba(7, 17, 27, .96));
    box-shadow: 0 0 22px rgba(77, 228, 250, .08);
}

.cs-sidebar-name {
    color: white;
    font-weight: 900;
    font-size: 16px;
    line-height: 1.05;
    letter-spacing: .35px;
}

.cs-sidebar-name span { color: var(--cs-cyan); }

.cs-sidebar-sub {
    margin-top: 5px;
    color: #56758e;
    font-size: 7px;
    letter-spacing: 2px;
    font-weight: 800;
}

.cs-user-card {
    border: 1px solid rgba(65, 94, 120, .42);
    border-radius: 13px;
    padding: 12px 13px;
    margin: 6px 0 10px 0;
    background: linear-gradient(145deg, rgba(18, 31, 46, .96), rgba(11, 21, 33, .96));
}

.cs-user-label {
    color: #5f7890;
    font-size: 8px;
    letter-spacing: 1.3px;
    font-weight: 800;
}

.cs-user-name {
    color: #eef7ff;
    font-weight: 800;
    margin-top: 3px;
    font-size: 13px;
}

.cs-role-pill {
    display: inline-block;
    margin-top: 8px;
    padding: 4px 8px;
    border-radius: 999px;
    border: 1px solid rgba(77, 228, 250, .28);
    color: #8cecf8;
    background: rgba(32, 169, 191, .08);
    font-size: 8px;
    letter-spacing: .5px;
    font-weight: 800;
}

.cs-mode-card {
    margin-top: 8px;
    padding: 10px 11px;
    border-radius: 11px;
    border: 1px solid rgba(70, 111, 136, .31);
    background: rgba(12, 23, 36, .80);
    color: #829ab0;
    font-size: 9px;
    line-height: 1.65;
}

.cs-live-dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #55d6a1;
    box-shadow: 0 0 10px rgba(85, 214, 161, .65);
    margin-right: 6px;
}

[data-testid="stSidebar"] [data-testid="stRadio"] > label {
    color: #587088 !important;
    font-size: 9px !important;
    letter-spacing: 1.4px !important;
    font-weight: 850 !important;
    margin-bottom: 7px;
}

[data-testid="stSidebar"] [role="radiogroup"] label {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 9px;
    padding: 7px 8px;
    margin: 2px 0;
    transition: all .16s ease;
}

[data-testid="stSidebar"] [role="radiogroup"] label:hover {
    background: rgba(77, 228, 250, .045);
    border-color: rgba(77, 228, 250, .13);
}

.cs-hero {
    position: relative;
    overflow: hidden;
    background:
        radial-gradient(circle at 88% 18%, rgba(77, 228, 250, .11), transparent 23%),
        linear-gradient(135deg, rgba(15, 31, 47, .96), rgba(9, 18, 30, .98));
    border: 1px solid rgba(67, 102, 131, .48);
    border-radius: 18px;
    padding: 24px 27px 23px 27px;
    margin-bottom: 22px;
    box-shadow: 0 18px 45px rgba(0, 0, 0, .20), inset 0 1px 0 rgba(255,255,255,.025);
}

.cs-hero:after {
    content: "";
    position: absolute;
    width: 230px;
    height: 230px;
    border: 1px solid rgba(77, 228, 250, .07);
    border-radius: 50%;
    right: -68px;
    top: -90px;
}

.cs-hero-top {
    display: flex;
    align-items: center;
    gap: 8px;
    color: #58ddec;
    font-size: 9px;
    font-weight: 850;
    letter-spacing: 1.9px;
    text-transform: uppercase;
}

.cs-hero-title {
    color: #f8fbff;
    font-size: 31px;
    line-height: 1.12;
    font-weight: 900;
    margin: 8px 0 8px 0;
}

.cs-hero-text {
    color: #8da1b4;
    font-size: 13px;
    max-width: 850px;
    line-height: 1.65;
}

.cs-hero-status {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    margin-top: 13px;
    padding: 6px 9px;
    border-radius: 999px;
    background: rgba(83, 205, 158, .07);
    border: 1px solid rgba(83, 205, 158, .18);
    color: #80d9b4;
    font-size: 9px;
    font-weight: 750;
}

[data-testid="stMetric"] {
    background: linear-gradient(145deg, rgba(16, 30, 46, .96), rgba(10, 20, 32, .98)) !important;
    border: 1px solid rgba(66, 96, 123, .43) !important;
    border-radius: 14px !important;
    padding: 16px 17px !important;
    min-height: 107px;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.018), 0 12px 26px rgba(0,0,0,.12);
}

[data-testid="stMetricLabel"] {
    color: #71869a !important;
    font-size: 10px !important;
    font-weight: 750 !important;
    letter-spacing: .45px;
}

[data-testid="stMetricValue"] {
    color: #f5f9ff !important;
    font-size: 25px !important;
    font-weight: 900 !important;
}

[data-testid="stForm"] {
    background: linear-gradient(145deg, rgba(16, 29, 44, .97), rgba(10, 20, 32, .98)) !important;
    border: 1px solid rgba(66, 97, 126, .43) !important;
    border-radius: 15px !important;
    padding: 18px !important;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.018);
}

.stTextInput input,
.stTextArea textarea,
.stNumberInput input,
.stSelectbox [data-baseweb="select"] > div,
.stTimeInput input {
    background: #101c2b !important;
    color: #eef7ff !important;
    border-color: #2b4258 !important;
    border-radius: 9px !important;
}

.stTextInput input:focus,
.stTextArea textarea:focus,
.stNumberInput input:focus {
    border-color: #45ddec !important;
    box-shadow: 0 0 0 1px rgba(69, 221, 236, .16) !important;
}

.stButton > button,
.stDownloadButton > button,
.stFormSubmitButton > button {
    min-height: 41px !important;
    border-radius: 9px !important;
    font-weight: 780 !important;
    border: 1px solid #30475d !important;
    background: linear-gradient(145deg, #142235, #101c2c) !important;
    color: #d9e5ef !important;
    transition: all .16s ease !important;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    border-color: rgba(77, 228, 250, .65) !important;
    color: #69e8f8 !important;
    transform: translateY(-1px);
}

.stButton > button[kind="primary"],
.stFormSubmitButton > button[kind="primary"] {
    background: linear-gradient(90deg, #35bfd8, #58ddf0) !important;
    border: none !important;
    color: #06131c !important;
    box-shadow: 0 8px 22px rgba(53, 191, 216, .13) !important;
}

[data-testid="stDataFrame"] {
    border: 1px solid rgba(63, 92, 118, .38) !important;
    border-radius: 13px !important;
    overflow: hidden;
    background: #0c1725;
}

[data-testid="stFileUploader"] {
    background: rgba(12, 24, 38, .75);
    border: 1px solid rgba(64, 95, 123, .32);
    border-radius: 13px;
    padding: 8px 12px 12px 12px;
}

[data-testid="stAlert"] {
    border-radius: 11px !important;
    border-width: 1px !important;
}

.stProgress > div > div > div > div {
    background: linear-gradient(90deg, #35bfd8, #58ddf0) !important;
}

[data-testid="stExpander"] {
    background: rgba(12, 23, 36, .76);
    border: 1px solid rgba(65, 93, 119, .36) !important;
    border-radius: 12px !important;
}

.cs-footer {
    text-align: center;
    color: #42566a;
    font-size: 9px;
    letter-spacing: .65px;
    border-top: 1px solid rgba(58, 83, 108, .28);
    padding-top: 18px;
    margin-top: 34px;
}

@media (max-width: 900px) {
    .cs-hero-title { font-size: 25px; }
    .block-container { padding-left: 1rem !important; padding-right: 1rem !important; }
}
</style>
""", unsafe_allow_html=True)

if not st.session_state[
    "authenticated"
]:
    show_login()
    st.stop()

permissions = role_permissions(
    st.session_state["role"]
)

page_options = []

if "dashboard" in permissions:
    page_options.append(
        "Dashboard"
    )

if "alerts" in permissions:
    page_options.append(
        "Alert Analysis"
    )

if "raw_logs" in permissions:
    page_options.append(
        "Raw Log Analysis"
    )

if "incidents" in permissions:
    page_options.append(
        "Incident Management"
    )

if "audit" in permissions:
    page_options.append(
        "Audit Trail"
    )

if "integrations" in permissions:
    page_options.append(
        "Integrations"
    )

if "testing" in permissions:
    page_options.append(
        "System Tests"
    )

if "about" in permissions:
    page_options.append(
        "About Platform"
    )

with st.sidebar:
    st.markdown(
        """
<div class="cs-sidebar-brand">
    <div class="cs-sidebar-logo">♢</div>
    <div>
        <div class="cs-sidebar-name">CYBERSHIELD <span>IQ</span></div>
        <div class="cs-sidebar-sub">SECURITY OPERATIONS</div>
    </div>
</div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        f"""
<div class="cs-user-card">
    <div class="cs-user-label">SIGNED IN AS</div>
    <div class="cs-user-name">{escape(st.session_state['username'])}</div>
    <div class="cs-role-pill">{escape(st.session_state['role'])}</div>
</div>
        """,
        unsafe_allow_html=True
    )

    page = st.radio(
        "WORKSPACE",
        page_options
    )

    st.markdown(
        f"""
<div class="cs-mode-card">
    <div><span class="cs-live-dot"></span><strong>SIMULATION MODE</strong></div>
    <div>{escape(GROUP_NAME)}</div>
    <div>Educational Prototype Environment</div>
</div>
        """,
        unsafe_allow_html=True
    )

    if st.button(
        "Sign Out",
        use_container_width=True,
        key="sidebar_signout"
    ):
        logout()

page_descriptions = {
    "Dashboard": (
        "Security Command Center",
        "Monitor simulated incidents, risk levels, analyst decisions, and SOC activity from one operational view."
    ),
    "Alert Analysis": (
        "Authentication Alert Analysis",
        "Evaluate suspicious login behavior, classify risk, and create a structured incident for human review."
    ),
    "Raw Log Analysis": (
        "Raw Security Log Analysis",
        "Ingest simulated authentication logs and identify brute-force, password-spraying, and compromise patterns."
    ),
    "Incident Management": (
        "Incident Investigation Workspace",
        "Search, review, assign, document, and export security incidents while preserving analyst control."
    ),
    "Audit Trail": (
        "Security Audit Trail",
        "Review recorded SOC actions and validate the integrity of hash-linked audit events."
    ),
    "Integrations": (
        "Security Integrations",
        "Review optional external service connectivity used by the educational prototype."
    ),
    "System Tests": (
        "Platform Self-Tests",
        "Validate database access, detection logic, audit integrity, and report generation before demonstration."
    ),
    "About Platform": (
        "About CyberShield IQ",
        "Explore the capabilities, boundaries, and human-control principles of the educational SOC prototype."
    )
}

hero_title, hero_text = page_descriptions.get(
    page,
    ("CyberShield IQ", "Enterprise Security Operations")
)

st.markdown(
    f"""
<div class="cs-hero">
    <div class="cs-hero-top">♢ CYBERSHIELD IQ · ENTERPRISE SOC</div>
    <div class="cs-hero-title">{escape(hero_title)}</div>
    <div class="cs-hero-text">{escape(hero_text)}</div>
    <div class="cs-hero-status"><span class="cs-live-dot"></span>SIMULATION ENVIRONMENT · HUMAN-CONTROLLED RESPONSE</div>
</div>
    """,
    unsafe_allow_html=True
)

if page == "Dashboard":
    render_dashboard()

elif page == "Alert Analysis":
    render_alert_analysis()

elif page == "Raw Log Analysis":
    render_raw_log_analysis()

elif page == "Incident Management":
    render_incident_management()

elif page == "Audit Trail":
    render_audit_trail()

elif page == "Integrations":
    render_integrations()

elif page == "System Tests":
    render_testing()

elif page == "About Platform":
    render_about()

st.markdown("""
<div class="cs-footer">
    CYBERSHIELD IQ &nbsp; · &nbsp; ENTERPRISE SECURITY OPERATIONS &nbsp; · &nbsp; GROUP 13 / PROJECT 20 &nbsp; · &nbsp; EDUCATIONAL SIMULATION
</div>
""", unsafe_allow_html=True)
