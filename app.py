import streamlit as st
import sqlite3
import csv
import io
import html
from pathlib import Path
from datetime import datetime, time

st.set_page_config(
    page_title="CyberShield Enterprise SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

DB_PATH = Path(__file__).resolve().parent / "cybershield_soc_v2.db"


def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def db_connection():
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
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

        # Add metadata without deleting existing incidents.
        existing_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(incidents)"
            )
        }

        for column in (
            "playbook_id",
            "playbook_reason",
            "playbook_source"
        ):
            if column not in existing_columns:
                connection.execute(
                    f"ALTER TABLE incidents ADD COLUMN {column} TEXT"
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


def incident_number(value):
    return f"INC-{value:04d}"


def escape(value):
    return html.escape(str(value))


def assess_risk(attempts, unfamiliar, successful):
    if attempts >= 3 and unfamiliar and successful:
        return (
            "HIGH",
            "Potential Account Compromise",
            "Multiple failed authentication attempts were followed "
            "by a successful login from an unfamiliar location."
        )

    if attempts == 0 and not unfamiliar and successful:
        return (
            "LOW",
            "Normal Authentication Activity",
            "The login matches the low-risk conditions defined "
            "in the current detection policy."
        )

    return (
        "UNCLEAR",
        "Manual Investigation Required",
        "The available authentication indicators do not provide "
        "enough evidence for a clear classification."
    )


# Documented response playbooks prepared for the simulation.
PLAYBOOKS = {
    "HIGH": {
        "id": "PB-002",
        "name": "Suspicious Authentication Investigation",
        "source": (
            "CyberShield Solutions - "
            "Internal Educational Response Playbook"
        ),
        "reason": (
            "Multiple failed logins, an unfamiliar location, "
            "and a successful login match the HIGH detection rule."
        ),
    },
    "LOW": {
        "id": "PB-001",
        "name": "Normal Authentication Monitoring",
        "source": (
            "CyberShield Solutions - "
            "Internal Educational Response Playbook"
        ),
        "reason": (
            "Zero failed attempts, a familiar location, "
            "and a successful login match the LOW detection rule."
        ),
    },
    "UNCLEAR": {
        "id": "PB-003",
        "name": "Evidence Collection and Manual Triage",
        "source": (
            "CyberShield Solutions - "
            "Internal Educational Response Playbook"
        ),
        "reason": (
            "The available indicators do not match a confirmed "
            "HIGH or LOW rule; manual investigation is required."
        ),
    },
}


def get_playbook(risk):
    return PLAYBOOKS.get(risk)


def create_incident(
    employee,
    login_time,
    attempts,
    unfamiliar,
    successful
):
    risk, classification, explanation = assess_risk(
        attempts,
        unfamiliar,
        successful
    )

    created = current_time()
    playbook = get_playbook(risk)

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
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            employee,
            str(login_time),
            attempts,
            int(unfamiliar),
            int(successful),
            risk,
            classification,
            explanation,
            playbook["id"] if playbook else None,
            (
                playbook["reason"]
                if playbook
                else "No matching playbook. Escalate for manual triage."
            ),
            (
                playbook["source"]
                if playbook
                else "No documented playbook available"
            ),
            created,
            created
        ))

        new_id = cursor.lastrowid

        connection.execute("""
            INSERT INTO audit_events (
                incident_id,
                event_type,
                description,
                created_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            new_id,
            "INCIDENT_CREATED",
            f"New authentication alert classified as {risk}.",
            created
        ))

    return new_id


def enrich_incident(item):
    """Add playbook details for older incident records."""
    playbook = get_playbook(item["risk"])

    if not item.get("playbook_id"):
        item["playbook_id"] = (
            playbook["id"]
            if playbook
            else "NOT ASSIGNED"
        )

    if not item.get("playbook_reason"):
        item["playbook_reason"] = (
            playbook["reason"]
            if playbook
            else "No matching playbook; manual triage required."
        )

    if not item.get("playbook_source"):
        item["playbook_source"] = (
            playbook["source"]
            if playbook
            else "No documented playbook available"
        )

    return item


def load_incidents():
    with db_connection() as connection:
        return [
            enrich_incident(dict(row))
            for row in connection.execute(
                "SELECT * FROM incidents ORDER BY id DESC"
            ).fetchall()
        ]


def load_incident(incident_id):
    with db_connection() as connection:
        row = connection.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

        return enrich_incident(dict(row)) if row else None


def load_audit_events():
    with db_connection() as connection:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM audit_events ORDER BY id DESC"
            ).fetchall()
        ]


def update_review(
    incident_id,
    decision,
    notes,
    verified,
    contacted,
    reviewed
):
    previous = load_incident(incident_id)

    if previous is None:
        return

    updated = current_time()

    with db_connection() as connection:
        connection.execute("""
            UPDATE incidents
            SET decision = ?,
                notes = ?,
                account_verified = ?,
                employee_contacted = ?,
                evidence_reviewed = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            decision,
            notes,
            int(verified),
            int(contacted),
            int(reviewed),
            updated,
            incident_id
        ))

        connection.execute("""
            INSERT INTO audit_events (
                incident_id,
                event_type,
                description,
                created_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            incident_id,
            "ANALYST_REVIEW",
            (
                f"Analyst decision changed from "
                f"{previous['decision']} to {decision}."
            ),
            updated
        ))


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

RISK ASSESSMENT

Risk Level: {item['risk']}
Classification: {item['classification']}
Assessment: {item['explanation']}

RESPONSE PLAYBOOK

Playbook ID: {item['playbook_id']}
Selection Reason: {item['playbook_reason']}
Playbook Source: {item['playbook_source']}
Execution Status: Recommendation only - no automated security action.

INVESTIGATION

Account Verified: {'YES' if item['account_verified'] else 'NO'}
Employee Contacted: {'YES' if item['employee_contacted'] else 'NO'}
Evidence Reviewed: {'YES' if item['evidence_reviewed'] else 'NO'}

ANALYST DECISION

{item['decision']}

ANALYST NOTES

{item['notes'] or 'No notes recorded.'}

AUDIT INFORMATION

Created At: {item['created_at']}
Updated At: {item['updated_at']}

==================================================
EDUCATIONAL PROTOTYPE
This report is generated from simulated data.
No real security actions were performed.
""".strip()


def incidents_csv(items):
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Incident ID",
        "Employee",
        "Login Time",
        "Failed Attempts",
        "Unfamiliar Location",
        "Successful Login",
        "Risk Level",
        "Classification",
        "Playbook ID",
        "Playbook Selection Reason",
        "Playbook Source",
        "Analyst Decision",
        "Notes",
        "Created At",
        "Updated At"
    ])

    for item in items:
        writer.writerow([
            incident_number(item["id"]),
            item["employee"],
            item["login_time"],
            item["failed_attempts"],
            "YES" if item["unfamiliar_location"] else "NO",
            "YES" if item["successful_login"] else "NO",
            item["risk"],
            item["classification"],
            item["playbook_id"],
            item["playbook_reason"],
            item["playbook_source"],
            item["decision"],
            item["notes"],
            item["created_at"],
            item["updated_at"]
        ])

    return output.getvalue().encode("utf-8-sig")


initialize_database()

if "active_incident" not in st.session_state:
    st.session_state.active_incident = None


# Application theme
st.markdown("""
<style>
.stApp {
    background:
        radial-gradient(
            circle at 85% 5%,
            rgba(39,92,167,.16),
            transparent 34%
        ),
        #08111f;
    color: #eaf2ff;
}

[data-testid="stSidebar"] {
    background: #0c192c;
    border-right: 1px solid #263b57;
}

[data-testid="stHeader"] {
    background: transparent;
}

.block-container {
    max-width: 1480px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

h1, h2, h3 {
    color: #f2f8ff !important;
    letter-spacing: -.4px;
}

[data-testid="stMetric"] {
    background: linear-gradient(135deg, #142943, #101e33);
    border: 1px solid #294562;
    border-radius: 17px;
    padding: 19px;
}

[data-testid="stMetricLabel"] {
    color: #a9bfd8;
}

[data-testid="stMetricValue"] {
    color: #73e0ef;
}

[data-testid="stForm"] {
    background: #101f34;
    border: 1px solid #2c4664;
    border-radius: 18px;
    padding: 20px;
}

.stButton > button[kind="primary"],
.stFormSubmitButton > button[kind="primary"] {
    background: linear-gradient(100deg, #008ea7, #4c60ce);
    border: none;
    color: white;
    font-weight: 700;
    border-radius: 10px;
}

.stButton > button:hover {
    border-color: #67dce9;
}

.hero {
    background: linear-gradient(
        115deg,
        #123d58,
        #192b52,
        #171e38
    );
    border: 1px solid #355e80;
    border-radius: 22px;
    padding: 34px;
    margin-bottom: 27px;
}

.eyebrow {
    color: #7de6ef;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 2px;
}

.hero-title {
    color: white;
    font-size: 35px;
    font-weight: 800;
    margin: 10px 0;
}

.hero-text {
    color: #c0d2e8;
    font-size: 15px;
    max-width: 820px;
}

.panel {
    background: #111f34;
    border: 1px solid #2a425f;
    border-radius: 17px;
    padding: 23px;
    margin: 12px 0;
}

.panel-title {
    font-size: 18px;
    color: #f1f7ff;
    font-weight: 750;
    margin-bottom: 8px;
}

.muted {
    font-size: 14px;
    color: #a1b7d2;
}

.risk-high {
    border-left: 5px solid #fb7185;
}

.risk-low {
    border-left: 5px solid #34d399;
}

.risk-unclear {
    border-left: 5px solid #fbbf24;
}

.risk-name {
    font-size: 32px;
    font-weight: 800;
    margin: 8px 0;
}

.high-color {
    color: #ff8a9d;
}

.low-color {
    color: #63e6b2;
}

.unclear-color {
    color: #f6d17d;
}

.step {
    background: #13253b;
    border: 1px solid #2c4561;
    border-radius: 12px;
    padding: 15px 18px;
    margin: 9px 0;
}

.step-index {
    color: #67dfec;
    font-size: 12px;
    font-weight: 800;
}

.step-title {
    color: #f2f8ff;
    font-size: 15px;
    font-weight: 700;
    margin-top: 4px;
}

.step-text {
    color: #a7bdd6;
    font-size: 13px;
    margin-top: 5px;
}

.footer {
    text-align: center;
    color: #7c94af;
    font-size: 12px;
    border-top: 1px solid #263a52;
    padding-top: 20px;
    margin-top: 40px;
}

@media (max-width: 700px) {
    .hero {
        padding: 20px;
    }

    .hero-title {
        font-size: 26px;
    }
}
</style>
""", unsafe_allow_html=True)


def section(title, description=""):
    st.subheader(title)

    if description:
        st.caption(description)


def show_risk(item):
    classes = {
        "HIGH": ("risk-high", "high-color"),
        "LOW": ("risk-low", "low-color"),
        "UNCLEAR": ("risk-unclear", "unclear-color")
    }

    border, color = classes.get(
        item["risk"],
        ("risk-unclear", "unclear-color")
    )

    st.markdown(f"""
    <div class="panel {border}">
        <div class="muted">DETECTED RISK LEVEL</div>
        <div class="risk-name {color}">
            {escape(item['risk'])}
        </div>
        <div class="panel-title">
            {escape(item['classification'])}
        </div>
        <div class="muted">
            {escape(item['explanation'])}
        </div>
    </div>
    """, unsafe_allow_html=True)


def show_step(number, title, description):
    st.markdown(f"""
    <div class="step">
        <div class="step-index">STEP {number}</div>
        <div class="step-title">{escape(title)}</div>
        <div class="step-text">{escape(description)}</div>
    </div>
    """, unsafe_allow_html=True)


def show_playbook(item):
    risk = item["risk"]

    section(
        "Recommended Response Playbook",
        "Guided recommendations requiring human review."
    )

    st.markdown(
        f"**Playbook ID:** `{escape(item['playbook_id'])}`"
    )
    st.caption(
        f"Playbook source: {item['playbook_source']}"
    )
    st.info(
        f"Selection rationale: {item['playbook_reason']}"
    )

    if risk not in PLAYBOOKS:
        st.error(
            "No matching response playbook is available. "
            "Escalate for manual analyst triage; do not approve "
            "containment based on this recommendation."
        )
        return

    if risk == "HIGH":
        st.warning(
            "High-priority investigation recommended. "
            "Human authorization is required before any response."
        )

        steps = [
            (
                "01",
                "Validate the Alert",
                "Review the authentication indicators and login timeline."
            ),
            (
                "02",
                "Verify the Account",
                "Confirm the affected account and available evidence."
            ),
            (
                "03",
                "Contact the Employee",
                "Verify the login using an approved communication channel."
            ),
            (
                "04",
                "Recommend Containment",
                "If compromise is confirmed, recommend approved "
                "account protection procedures."
            ),
            (
                "05",
                "Escalate and Document",
                "Escalate to the responsible team and document the findings."
            )
        ]

    elif risk == "LOW":
        st.success(
            "No immediate response is indicated by the current rules."
        )

        steps = [
            (
                "01",
                "Document the Event",
                "Record the authentication activity."
            ),
            (
                "02",
                "Continue Monitoring",
                "Watch for additional suspicious indicators."
            )
        ]

    else:
        st.warning(
            "No confirmed containment playbook applies. "
            "PB-003 is an investigative fallback only; "
            "collect additional evidence before any response decision."
        )

        steps = [
            (
                "01",
                "Collect Evidence",
                "Review available authentication records."
            ),
            (
                "02",
                "Validate Context",
                "Confirm account details, location, and login outcome."
            ),
            (
                "03",
                "Request Analyst Review",
                "Reassess the alert after reviewing the evidence."
            )
        ]

    for number, title, description in steps:
        show_step(number, title, description)


def show_details(item):
    section("Incident Summary")

    a, b, c = st.columns(3)
    a.metric("Incident ID", incident_number(item["id"]))
    b.metric("Employee Account", item["employee"])
    c.metric("Failed Attempts", item["failed_attempts"])

    d, e, f = st.columns(3)
    d.metric("Login Time", item["login_time"])
    e.metric(
        "Unfamiliar Location",
        "YES" if item["unfamiliar_location"] else "NO"
    )
    f.metric(
        "Successful Login",
        "YES" if item["successful_login"] else "NO"
    )

    st.divider()
    section("Threat Assessment")
    show_risk(item)

    st.divider()
    show_playbook(item)


def show_analyst_workspace(item):
    st.divider()

    section(
        "Security Analyst Workspace",
        "Complete investigation checks, save notes, and record a decision."
    )

    st.info(
        "Approving a recommendation records a decision only. "
        "It does not execute real security actions."
    )

    decisions = ["Pending Review", "Approve", "Reject"]

    with st.form(f"review_form_{item['id']}"):
        st.markdown("#### Investigation Checklist")

        verified = st.checkbox(
            "Employee account and identity verified",
            value=bool(item["account_verified"])
        )

        contacted = st.checkbox(
            "Employee contacted through an approved channel",
            value=bool(item["employee_contacted"])
        )

        reviewed = st.checkbox(
            "Authentication evidence reviewed",
            value=bool(item["evidence_reviewed"])
        )

        st.markdown("#### Analyst Notes")

        notes = st.text_area(
            "Investigation Notes",
            value=item["notes"],
            height=130,
            placeholder="Record observations, evidence, and next steps."
        )

        decision = st.radio(
            "Analyst Decision",
            decisions,
            index=(
                decisions.index(item["decision"])
                if item["decision"] in decisions
                else 0
            ),
            horizontal=True
        )

        save = st.form_submit_button(
            "Save Analyst Review",
            type="primary",
            use_container_width=True
        )

    if save:
        update_review(
            item["id"],
            decision,
            notes,
            verified,
            contacted,
            reviewed
        )
        st.rerun()

    if item["decision"] == "Approve":
        st.success("Analyst recommendation approved.")

    elif item["decision"] == "Reject":
        st.error("Analyst recommendation rejected.")

    else:
        st.info("This incident is awaiting analyst review.")

    completed = sum([
        bool(item["account_verified"]),
        bool(item["employee_contacted"]),
        bool(item["evidence_reviewed"])
    ])

    st.markdown("#### Investigation Progress")
    st.progress(completed / 3)
    st.caption(f"{completed} of 3 checks completed.")

    st.download_button(
        "Download Incident Report",
        data=incident_report(item),
        file_name=f"{incident_number(item['id'])}_report.txt",
        mime="text/plain",
        use_container_width=True,
        key=f"report_{item['id']}"
    )


# Navigation
with st.sidebar:
    st.markdown("## 🛡️ CYBERSHIELD")
    st.caption("ENTERPRISE SECURITY OPERATIONS")
    st.divider()

    page = st.radio(
        "WORKSPACE",
        [
            "Dashboard",
            "Alert Analysis",
            "Incident Management",
            "Audit Trail",
            "About Platform"
        ]
    )

    st.divider()
    st.success("● SIMULATION MODE")
    st.caption("CyberShield Solutions")
    st.caption("Group 13 | Project 20")
    st.caption("Prototype Environment")


st.markdown("""
<div class="hero">
    <div class="eyebrow">
        ENTERPRISE SECURITY OPERATIONS CENTER
    </div>
    <div class="hero-title">
        CyberShield Enterprise
    </div>
    <div class="hero-text">
        Transparent security risk assessment, guided incident
        investigations, and human-controlled response decisions.
    </div>
</div>
""", unsafe_allow_html=True)


if page == "Dashboard":
    items = load_incidents()

    total = len(items)
    high = sum(i["risk"] == "HIGH" for i in items)
    low = sum(i["risk"] == "LOW" for i in items)
    unclear = sum(i["risk"] == "UNCLEAR" for i in items)

    section(
        "Security Command Center",
        "Real-time view of locally recorded simulation incidents."
    )

    a, b, c, d = st.columns(4)
    a.metric("Total Incidents", total)
    b.metric("High Risk", high)
    c.metric("Low Risk", low)
    d.metric("Needs Investigation", unclear)

    st.divider()

    left, right = st.columns([1.4, 1])

    with left:
        section("Threat Distribution")

        if total:
            st.write(f"High Risk — {high}")
            st.progress(high / total)

            st.write(f"Low Risk — {low}")
            st.progress(low / total)

            st.write(f"Unclear Risk — {unclear}")
            st.progress(unclear / total)

        else:
            st.info(
                "No incidents recorded. "
                "Submit your first security alert."
            )

    with right:
        section("Operational Workflow")

        st.markdown("""
        <div class="panel">
            <p>01 — Submit Security Alert</p>
            <p>02 — Assess Risk Indicators</p>
            <p>03 — Review Response Playbook</p>
            <p>04 — Investigate and Document</p>
            <p>05 — Record Analyst Decision</p>
            <p>06 — Export Incident Report</p>
        </div>
        """, unsafe_allow_html=True)

    st.divider()
    section("Analyst Decision Overview")

    approved = sum(
        i["decision"] == "Approve"
        for i in items
    )
    rejected = sum(
        i["decision"] == "Reject"
        for i in items
    )
    pending = sum(
        i["decision"] == "Pending Review"
        for i in items
    )

    x, y, z = st.columns(3)
    x.metric("Approved", approved)
    y.metric("Rejected", rejected)
    z.metric("Pending Review", pending)

    if items:
        st.divider()
        section("Recent Incidents")

        recent_rows = [
            {
                "Incident ID": incident_number(i["id"]),
                "Employee": i["employee"],
                "Risk": i["risk"],
                "Decision": i["decision"],
                "Created At": i["created_at"]
            }
            for i in items[:5]
        ]

        st.dataframe(
            recent_rows,
            use_container_width=True,
            hide_index=True
        )


elif page == "Alert Analysis":
    section(
        "Security Alert Analysis",
        "Choose a test scenario or enter a simulated authentication event."
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
            "employee01", 0, False, False
        ),
        "High Risk Example": (
            "employee_high", 5, True, True
        ),
        "Low Risk Example": (
            "employee_low", 0, False, True
        ),
        "Unclear Risk Example": (
            "employee_review", 2, True, False
        )
    }

    (
        employee_default,
        attempts_default,
        unfamiliar_default,
        success_default
    ) = samples[scenario]

    with st.form(f"alert_form_{scenario}"):
        a, b = st.columns(2)

        with a:
            employee = st.text_input(
                "Employee Account",
                value=employee_default,
                max_chars=100
            )

            login_time = st.time_input(
                "Login Time",
                value=time(9, 0)
            )

        with b:
            attempts = st.number_input(
                "Failed Login Attempts",
                min_value=0,
                max_value=100,
                value=attempts_default,
                step=1
            )

        st.markdown("#### Authentication Indicators")

        unfamiliar = st.checkbox(
            "Login from an unfamiliar location",
            value=unfamiliar_default
        )

        successful = st.checkbox(
            "Successful login",
            value=success_default
        )

        analyze = st.form_submit_button(
            "Analyze and Create Incident",
            type="primary",
            use_container_width=True
        )

    if analyze:
        if not employee.strip():
            st.error("Employee Account is required.")

        else:
            incident_id = create_incident(
                employee.strip(),
                login_time,
                int(attempts),
                unfamiliar,
                successful
            )

            st.session_state.active_incident = incident_id
            st.rerun()

    if st.session_state.active_incident is not None:
        item = load_incident(
            st.session_state.active_incident
        )

        if item:
            st.divider()

            st.success(
                f"{incident_number(item['id'])} created successfully."
            )

            show_details(item)
            show_analyst_workspace(item)

    else:
        st.info(
            "Submit an alert to generate a risk assessment "
            "and open the analyst investigation workspace."
        )


elif page == "Incident Management":
    section(
        "Incident Management",
        "Search, review, and export recorded security incidents."
    )

    items = load_incidents()

    if not items:
        st.info("No incidents have been recorded yet.")

    else:
        a, b = st.columns([2, 1])

        with a:
            search = st.text_input(
                "Search Incidents",
                placeholder="Employee account or incident ID"
            )

        with b:
            risk_filter = st.selectbox(
                "Risk Filter",
                ["ALL", "HIGH", "LOW", "UNCLEAR"]
            )

        filtered = [
            item
            for item in items
            if (
                search.lower() in item["employee"].lower()
                or search.lower()
                in incident_number(item["id"]).lower()
            )
            and (
                risk_filter == "ALL"
                or item["risk"] == risk_filter
            )
        ]

        st.caption(
            f"Showing {len(filtered)} of {len(items)} incidents."
        )

        if filtered:
            rows = [
                {
                    "Incident ID": incident_number(i["id"]),
                    "Employee": i["employee"],
                    "Risk Level": i["risk"],
                    "Classification": i["classification"],
                    "Playbook ID": i["playbook_id"],
                    "Decision": i["decision"],
                    "Created At": i["created_at"]
                }
                for i in filtered
            ]

            st.dataframe(
                rows,
                use_container_width=True,
                hide_index=True
            )

            st.download_button(
                "Export Filtered Incidents (CSV)",
                data=incidents_csv(filtered),
                file_name="cybershield_incidents.csv",
                mime="text/csv",
                use_container_width=True
            )

            st.divider()
            section("Open Investigation")

            options = [
                i["id"]
                for i in filtered
            ]

            selected_id = st.selectbox(
                "Select Incident",
                options,
                format_func=lambda value: (
                    f"{incident_number(value)} — "
                    f"{next(i['employee'] for i in filtered if i['id'] == value)}"
                )
            )

            selected_item = load_incident(selected_id)

            if selected_item:
                show_details(selected_item)
                show_analyst_workspace(selected_item)

        else:
            st.warning(
                "No incidents match the selected filters."
            )


elif page == "Audit Trail":
    section(
        "Security Audit Trail",
        "History of incident creation and analyst review events."
    )

    events = load_audit_events()

    if not events:
        st.info("No audit events recorded.")

    else:
        rows = [
            {
                "Event ID": event["id"],
                "Incident ID": (
                    incident_number(event["incident_id"])
                    if event["incident_id"] is not None
                    else "N/A"
                ),
                "Event Type": event["event_type"],
                "Description": event["description"],
                "Timestamp": event["created_at"]
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
            fieldnames=list(rows[0].keys())
        )

        writer.writeheader()
        writer.writerows(rows)

        st.download_button(
            "Export Audit Trail (CSV)",
            data=output.getvalue().encode("utf-8-sig"),
            file_name="cybershield_audit.csv",
            mime="text/csv"
        )

        st.caption(
            "Audit records are stored locally "
            "and are not tamper-proof."
        )


elif page == "About Platform":
    section("About CyberShield Enterprise SOC")

    st.markdown("""
    ### Platform Overview

    CyberShield Enterprise SOC is an educational security
    operations prototype designed to demonstrate transparent
    risk assessment and human-guided incident response.

    ### Core Capabilities

    - Simulated authentication alert analysis
    - Rule-based risk classification
    - Guided security response playbooks
    - Playbook IDs and matching explanations
    - Documented playbook reference sources
    - Analyst investigation checklists
    - Incident notes and decision management
    - Persistent local incident records
    - Search and risk filtering
    - Downloadable incident reports
    - CSV exports
    - Local audit event tracking

    ### Risk Classification Policy

    **HIGH**

    Three or more failed login attempts, an unfamiliar
    location, and a successful login.

    **LOW**

    Zero failed login attempts, a familiar location,
    and a successful login.

    **UNCLEAR**

    Any other combination requiring further investigation.

    ### Response Playbook Mapping

    - LOW: PB-001
    - HIGH: PB-002
    - UNCLEAR: PB-003

    The system recommends a documented response playbook
    based on the assessed risk category.

    The playbook ID, selection reason, and internal
    reference source are displayed for analyst review.

    An unrecognized risk category does not receive
    an invented playbook. Manual triage is required.

    ### Technology Stack

    - Python
    - Streamlit
    - SQLite
    - Rule-based detection logic

    ### Security and Deployment Limitations

    This prototype does not connect to real authentication
    systems or execute live security response actions.

    It does not include production authentication,
    role-based access control, encrypted storage,
    or a trained artificial intelligence model.

    The application is intended for local demonstration
    using fictional or simulated information.

    SQLite storage is local to the application instance.
    Cloud hosting does not guarantee durable persistence
    across restarts or redeployments.

    ### Future Development

    - Secure analyst authentication
    - Role-based access control
    - Security platform integrations
    - Advanced detection models
    - Centralized protected storage
    - Secure API integrations
    - Tamper-resistant audit logging
    - Production security assessment
    """)

    st.info(
        "This is an educational prototype, "
        "not a production-ready security system."
    )


st.markdown("""
<div class="footer">
    CYBERSHIELD ENTERPRISE SOC
    &nbsp; | &nbsp;
    SECURITY OPERATIONS CENTER
    &nbsp; | &nbsp;
    PROJECT 20
    &nbsp; | &nbsp;
    SIMULATION ENVIRONMENT
</div>
""", unsafe_allow_html=True)
