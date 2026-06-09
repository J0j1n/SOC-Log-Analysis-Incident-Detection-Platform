"""
SOC Log Analysis, Alert Management & Incident Response Platform
================================================================
Main Streamlit application — entry point.

Run with:
    streamlit run app.py
"""

import os
import sys
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so module imports work
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Module imports
# ---------------------------------------------------------------------------
from modules.auth import (
    authenticate_user,
    create_user,
    delete_user,
    get_all_users,
    update_user_role,
)
from modules.rbac import (
    check_permission,
    require_permission,
    get_accessible_pages,
    PERMISSIONS,
)
from modules.audit import (
    log_action,
    get_audit_logs,
    get_audit_actions,
    LOGIN,
    LOGOUT,
    FAILED_LOGIN,
    UPLOAD_LOG,
    RUN_DETECTION,
    CREATE_ALERT,
    INVESTIGATE_ALERT,
    UPDATE_ALERT,
    CREATE_INCIDENT,
    UPDATE_INCIDENT,
    CLOSE_INCIDENT,
    CREATE_USER as AUDIT_CREATE_USER,
    DELETE_USER as AUDIT_DELETE_USER,
    UPDATE_ROLE,
    GENERATE_REPORT,
)
from modules.parser import parse_log_file, store_parsed_logs, get_uploaded_logs
from modules.detector import run_all_detections
from modules.alerts import (
    create_alerts_from_detections,
    get_alerts,
    get_alert_by_id,
    update_alert_status,
    get_alert_stats,
    add_investigation_note,
    get_investigation_notes,
)
from modules.incidents import (
    create_incident,
    get_incidents,
    get_incident_by_id,
    update_incident_status,
    get_incident_stats,
    get_incident_timeline,
)
from modules.reports import generate_incident_report, get_generated_reports

# ---------------------------------------------------------------------------
# Auto-initialize database on first run
# ---------------------------------------------------------------------------
from database.init_db import initialize_database, DB_PATH as INIT_DB_PATH

if not os.path.exists(INIT_DB_PATH):
    initialize_database()

# ═══════════════════════════════════════════════════════════════════════════
# PAGE CONFIG & CUSTOM CSS
# ═══════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="SOC Platform — Incident Response",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
    /* ── Global Dark Theme ────────────────────────────────────── */
    .stApp {
        background: linear-gradient(135deg, #0f0c29 0%, #1a1a2e 50%, #16213e 100%);
        color: #e0e0e0;
    }
    .stSidebar > div:first-child {
        background: linear-gradient(180deg, #0f0c29 0%, #1a1a2e 100%);
    }

    /* ── KPI Cards ────────────────────────────────────────────── */
    .kpi-card {
        background: linear-gradient(135deg, #16213e 0%, #0f3460 100%);
        border: 1px solid #0f346066;
        border-radius: 12px;
        padding: 20px 16px;
        text-align: center;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .kpi-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 25px rgba(15,52,96,0.5);
    }
    .kpi-value {
        font-size: 2.2rem;
        font-weight: 800;
        color: #e94560;
        line-height: 1.1;
    }
    .kpi-label {
        font-size: 0.85rem;
        color: #8892b0;
        margin-top: 6px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* ── Status Badges ────────────────────────────────────────── */
    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.5px;
    }
    .badge-critical { background: #e94560; color: white; }
    .badge-high     { background: #ff6b35; color: white; }
    .badge-medium   { background: #f0a500; color: #1a1a2e; }
    .badge-low      { background: #48bfe3; color: #1a1a2e; }
    .badge-open     { background: #e94560; color: white; }
    .badge-investigating,
    .badge-under_investigation { background: #f0a500; color: #1a1a2e; }
    .badge-contained  { background: #48bfe3; color: #1a1a2e; }
    .badge-resolved   { background: #06d6a0; color: #1a1a2e; }
    .badge-closed     { background: #6c757d; color: white; }
    .badge-false_positive { background: #6c757d; color: white; }

    /* ── Sidebar Styling ──────────────────────────────────────── */
    .sidebar-header {
        text-align: center;
        padding: 10px 0 20px;
        border-bottom: 1px solid #0f346066;
        margin-bottom: 16px;
    }
    .sidebar-header h2 {
        color: #e94560;
        font-size: 1.3rem;
        margin: 0;
    }
    .sidebar-header p {
        color: #8892b0;
        font-size: 0.8rem;
        margin: 2px 0 0;
    }

    /* ── Section Headers ──────────────────────────────────────── */
    .section-header {
        color: #ccd6f6;
        border-bottom: 2px solid #e94560;
        padding-bottom: 8px;
        margin-bottom: 16px;
        font-size: 1.4rem;
    }

    /* ── Data Tables ──────────────────────────────────────────── */
    .stDataFrame { border-radius: 8px; overflow: hidden; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def severity_badge(severity: str) -> str:
    s = severity.lower()
    return f'<span class="badge badge-{s}">{severity}</span>'


def status_badge(status: str) -> str:
    s = status.lower().replace(" ", "_")
    return f'<span class="badge badge-{s}">{status}</span>'


def kpi_card(value, label: str) -> str:
    return f"""
    <div class="kpi-card">
        <div class="kpi-value">{value}</div>
        <div class="kpi-label">{label}</div>
    </div>"""


# ═══════════════════════════════════════════════════════════════════════════
# SESSION STATE INIT
# ═══════════════════════════════════════════════════════════════════════════
for key, default in {
    "logged_in": False,
    "username": "",
    "role": "",
    "current_page": "Dashboard",
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


# ═══════════════════════════════════════════════════════════════════════════
# LOGIN PAGE
# ═══════════════════════════════════════════════════════════════════════════

def render_login():
    """Render the full-screen login form."""
    col_l, col_c, col_r = st.columns([1, 2, 1])
    with col_c:
        st.markdown("---")
        st.markdown(
            "<h1 style='text-align:center;color:#e94560;'>🛡️ SOC Platform</h1>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p style='text-align:center;color:#8892b0;'>Log Analysis • Alert Management • Incident Response</p>",
            unsafe_allow_html=True,
        )
        st.markdown("---")

        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("🔐 Sign In", use_container_width=True)

        if submitted:
            if not username or not password:
                st.error("Please enter both username and password.")
                return

            user = authenticate_user(username, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.username = user["username"]
                st.session_state.role = user["role"]
                st.session_state.current_page = "Dashboard"
                log_action(user["username"], LOGIN, "Successful login")
                st.rerun()
            else:
                log_action(username, FAILED_LOGIN, "Invalid credentials attempt")
                st.error("⛔ Invalid credentials. Please try again.")

        st.markdown(
            "<p style='text-align:center;color:#555;font-size:0.8rem;margin-top:30px;'>"
            "Default: admin / Admin@123</p>",
            unsafe_allow_html=True,
        )


# ═══════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════

def render_sidebar():
    """Render the RBAC-gated sidebar navigation."""
    with st.sidebar:
        st.markdown(
            f"""<div class="sidebar-header">
                <h2>🛡️ SOC Platform</h2>
                <p>{st.session_state.username} • {st.session_state.role.replace('_', ' ')}</p>
            </div>""",
            unsafe_allow_html=True,
        )

        pages = get_accessible_pages(st.session_state.role)
        # Map pages to icons
        icons = {
            "Dashboard": "📊",
            "Upload Logs": "📤",
            "Alerts": "🚨",
            "Investigations": "🔍",
            "Incidents": "🔥",
            "Reports": "📄",
            "User Management": "👥",
            "Audit Logs": "📋",
        }

        for page in pages:
            icon = icons.get(page, "📌")
            if st.button(
                f"{icon}  {page}",
                key=f"nav_{page}",
                use_container_width=True,
            ):
                st.session_state.current_page = page
                st.rerun()

        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            log_action(st.session_state.username, LOGOUT, "User logged out")
            for k in ["logged_in", "username", "role", "current_page"]:
                st.session_state[k] = "" if k != "logged_in" else False
            st.session_state.current_page = "Dashboard"
            st.rerun()


# ═══════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════

def page_dashboard():
    st.markdown('<h2 class="section-header">📊 Security Operations Dashboard</h2>', unsafe_allow_html=True)

    # ── KPI Row ───────────────────────────────────────────────
    alert_stats = get_alert_stats()
    incident_stats = get_incident_stats()
    logs = get_uploaded_logs(limit=99999)

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(kpi_card(len(logs), "Total Logs"), unsafe_allow_html=True)
    with c2:
        st.markdown(kpi_card(alert_stats["total"], "Total Alerts"), unsafe_allow_html=True)
    with c3:
        st.markdown(kpi_card(alert_stats["critical"], "Critical Alerts"), unsafe_allow_html=True)
    with c4:
        st.markdown(kpi_card(incident_stats["open"], "Open Incidents"), unsafe_allow_html=True)
    with c5:
        st.markdown(kpi_card(incident_stats["resolved"] + incident_stats["closed"], "Resolved"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts ────────────────────────────────────────────────
    chart_l, chart_r = st.columns(2)

    with chart_l:
        # Severity distribution donut chart
        sev_data = {
            "Severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            "Count": [
                alert_stats["critical"],
                alert_stats["high"],
                alert_stats["medium"],
                alert_stats["low"],
            ],
        }
        sev_df = pd.DataFrame(sev_data)
        sev_df = sev_df[sev_df["Count"] > 0]

        if not sev_df.empty:
            fig_sev = px.pie(
                sev_df,
                values="Count",
                names="Severity",
                hole=0.45,
                color="Severity",
                color_discrete_map={
                    "CRITICAL": "#e94560",
                    "HIGH": "#ff6b35",
                    "MEDIUM": "#f0a500",
                    "LOW": "#48bfe3",
                },
            )
            fig_sev.update_layout(
                title="Alert Severity Distribution",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#ccd6f6",
                legend=dict(font=dict(color="#8892b0")),
                margin=dict(t=40, b=10, l=10, r=10),
            )
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.info("No alerts to display yet.")

    with chart_r:
        # Incident status bar chart
        inc_data = {
            "Status": ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"],
            "Count": [
                incident_stats["open"],
                incident_stats["investigating"],
                incident_stats["contained"],
                incident_stats["resolved"],
                incident_stats["closed"],
            ],
        }
        inc_df = pd.DataFrame(inc_data)

        if inc_df["Count"].sum() > 0:
            fig_inc = px.bar(
                inc_df,
                x="Status",
                y="Count",
                color="Status",
                color_discrete_map={
                    "OPEN": "#e94560",
                    "INVESTIGATING": "#f0a500",
                    "CONTAINED": "#48bfe3",
                    "RESOLVED": "#06d6a0",
                    "CLOSED": "#6c757d",
                },
            )
            fig_inc.update_layout(
                title="Incident Status Overview",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#ccd6f6",
                xaxis=dict(color="#8892b0"),
                yaxis=dict(color="#8892b0"),
                showlegend=False,
                margin=dict(t=40, b=10, l=10, r=10),
            )
            st.plotly_chart(fig_inc, use_container_width=True)
        else:
            st.info("No incidents to display yet.")

    # ── MITRE ATT&CK coverage ────────────────────────────────
    all_alerts = get_alerts(limit=9999)
    if all_alerts:
        mitre_df = pd.DataFrame(all_alerts)
        if "mitre_technique_id" in mitre_df.columns:
            mitre_counts = (
                mitre_df[mitre_df["mitre_technique_id"].notna() & (mitre_df["mitre_technique_id"] != "")]
                .groupby(["mitre_technique_id", "mitre_technique_name"])
                .size()
                .reset_index(name="Count")
            )
            if not mitre_counts.empty:
                mitre_counts["label"] = mitre_counts["mitre_technique_id"] + " — " + mitre_counts["mitre_technique_name"]
                fig_mitre = px.bar(
                    mitre_counts,
                    x="label",
                    y="Count",
                    color="Count",
                    color_continuous_scale=["#16213e", "#e94560"],
                )
                fig_mitre.update_layout(
                    title="MITRE ATT&CK Technique Coverage",
                    xaxis_title="Technique",
                    yaxis_title="Alert Count",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#ccd6f6",
                    margin=dict(t=40, b=10, l=10, r=10),
                )
                st.plotly_chart(fig_mitre, use_container_width=True)

    # ── Recent Alerts & Incidents Tables ──────────────────────
    tbl_l, tbl_r = st.columns(2)

    with tbl_l:
        st.markdown("#### 🚨 Recent Alerts")
        recent_alerts = get_alerts(limit=10)
        if recent_alerts:
            for a in recent_alerts:
                with st.container():
                    st.markdown(
                        f"**{a['alert_id']}** — {a['threat_type']}  "
                        f"{severity_badge(a['severity'])} {status_badge(a['status'])}  "
                        f"<small style='color:#8892b0'>({a['timestamp']})</small>",
                        unsafe_allow_html=True,
                    )
        else:
            st.info("No alerts yet. Upload logs and run detection.")

    with tbl_r:
        st.markdown("#### 🔥 Recent Incidents")
        recent_incidents = get_incidents(limit=10)
        if recent_incidents:
            for inc in recent_incidents:
                with st.container():
                    st.markdown(
                        f"**{inc['incident_id']}** — {inc['threat_type']}  "
                        f"{severity_badge(inc['severity'])} {status_badge(inc['status'])}  "
                        f"<small style='color:#8892b0'>({inc['created_at']})</small>",
                        unsafe_allow_html=True,
                    )
        else:
            st.info("No incidents yet.")


# ═══════════════════════════════════════════════════════════════════════════
# PAGE: UPLOAD LOGS
# ═══════════════════════════════════════════════════════════════════════════

def page_upload_logs():
    require_permission(st.session_state.role, "upload_logs")
    st.markdown('<h2 class="section-header">📤 Upload & Analyze Security Logs</h2>', unsafe_allow_html=True)

    tab_upload, tab_view = st.tabs(["📂 Upload Logs", "📋 View Uploaded Logs"])

    with tab_upload:
        uploaded_file = st.file_uploader(
            "Upload a log file (.txt or .csv)",
            type=["txt", "csv"],
            help="Supported format: timestamp event_type username [source_ip]",
        )

        col_sample, _ = st.columns([1, 2])
        with col_sample:
            use_sample = st.checkbox("Load sample logs instead")

        if use_sample:
            sample_txt = os.path.join(PROJECT_ROOT, "sample_logs", "auth_logs.txt")
            if os.path.exists(sample_txt):
                with open(sample_txt, "r") as f:
                    content = f.read()
                filename = "auth_logs.txt"
                st.info(f"Loaded sample file: **{filename}** ({len(content)} bytes)")
            else:
                st.error("Sample log file not found.")
                return
        elif uploaded_file:
            content = uploaded_file.getvalue().decode("utf-8")
            filename = uploaded_file.name
        else:
            st.info("Upload a log file or check 'Load sample logs' to get started.")
            return

        # Parse
        events, errors = parse_log_file(filename, content)

        if errors:
            with st.expander(f"⚠️ {len(errors)} parsing warnings", expanded=False):
                for err in errors:
                    st.warning(err)

        if events:
            st.success(f"✅ Parsed **{len(events)}** events from `{filename}`")

            # Preview
            preview_df = pd.DataFrame(events[:20])
            st.dataframe(preview_df, use_container_width=True, height=300)

            col_store, col_detect = st.columns(2)

            with col_store:
                if st.button("💾 Store Logs in Database", use_container_width=True):
                    count = store_parsed_logs(events, st.session_state.username)
                    log_action(st.session_state.username, UPLOAD_LOG, f"Stored {count} log events from {filename}")
                    st.success(f"✅ Stored **{count}** events in the database.")

            with col_detect:
                if st.button("🔍 Run Detection Engine", type="primary", use_container_width=True):
                    # Store first if not already stored
                    store_parsed_logs(events, st.session_state.username)

                    df = pd.DataFrame(events)
                    detections = run_all_detections(df)
                    log_action(st.session_state.username, RUN_DETECTION, f"Detection run: {len(detections)} findings")

                    if detections:
                        new_alerts = create_alerts_from_detections(detections)
                        log_action(
                            st.session_state.username,
                            CREATE_ALERT,
                            f"Created {new_alerts} alerts from detection",
                        )
                        st.success(f"🚨 Detection complete: **{new_alerts}** new alerts generated!")

                        # Show detections
                        with st.expander("View Detection Results", expanded=True):
                            for d in detections:
                                st.markdown(
                                    f"- **{d['threat_type']}** {severity_badge(d['severity'])} "
                                    f"— {d.get('description', '')} "
                                    f"[{d.get('mitre_technique_id', '')}]",
                                    unsafe_allow_html=True,
                                )
                    else:
                        st.info("✅ No threats detected in the uploaded logs.")
        else:
            st.warning("No events could be parsed from the file.")

    with tab_view:
        logs = get_uploaded_logs(limit=500)
        if logs:
            log_df = pd.DataFrame(logs)
            display_cols = ["timestamp", "event_type", "username", "source_ip", "log_source", "uploaded_by", "uploaded_at"]
            available_cols = [c for c in display_cols if c in log_df.columns]
            st.dataframe(log_df[available_cols], use_container_width=True, height=500)
            st.caption(f"Showing {len(logs)} most recent log entries")
        else:
            st.info("No logs uploaded yet.")


# ═══════════════════════════════════════════════════════════════════════════
# PAGE: ALERTS
# ═══════════════════════════════════════════════════════════════════════════

def page_alerts():
    require_permission(st.session_state.role, "view_alerts")
    st.markdown('<h2 class="section-header">🚨 Alert Management</h2>', unsafe_allow_html=True)

    # Filters
    fc1, fc2, fc3 = st.columns(3)
    with fc1:
        status_f = st.selectbox("Filter by Status", ["ALL", "OPEN", "UNDER_INVESTIGATION", "FALSE_POSITIVE", "CLOSED"])
    with fc2:
        severity_f = st.selectbox("Filter by Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with fc3:
        limit = st.slider("Max results", 10, 500, 100)

    alerts = get_alerts(
        status_filter=status_f if status_f != "ALL" else None,
        severity_filter=severity_f if severity_f != "ALL" else None,
        limit=limit,
    )

    if not alerts:
        st.info("No alerts match your filters.")
        return

    st.caption(f"Showing {len(alerts)} alert(s)")

    for alert in alerts:
        with st.expander(
            f"{alert['alert_id']} — {alert['threat_type']} | {alert['severity']} | {alert['status']}",
            expanded=False,
        ):
            col_info, col_mitre = st.columns(2)

            with col_info:
                st.markdown(f"**Alert ID:** {alert['alert_id']}")
                st.markdown(f"**Threat Type:** {alert['threat_type']}")
                st.markdown(f"**Severity:** {severity_badge(alert['severity'])}", unsafe_allow_html=True)
                st.markdown(f"**Status:** {status_badge(alert['status'])}", unsafe_allow_html=True)
                st.markdown(f"**Source IP:** {alert.get('source_ip', 'N/A')}")
                st.markdown(f"**Affected User:** {alert.get('affected_user', 'N/A')}")
                st.markdown(f"**Timestamp:** {alert['timestamp']}")

            with col_mitre:
                st.markdown("**MITRE ATT&CK Mapping:**")
                st.markdown(f"- **Tactic:** {alert.get('mitre_tactic', 'N/A')}")
                st.markdown(f"- **Technique ID:** {alert.get('mitre_technique_id', 'N/A')}")
                st.markdown(f"- **Technique Name:** {alert.get('mitre_technique_name', 'N/A')}")

            st.markdown(f"**Description:** {alert.get('description', 'N/A')}")

            # ── Actions ───────────────────────────────────────
            st.markdown("---")
            act1, act2 = st.columns(2)

            with act1:
                if check_permission(st.session_state.role, "investigate_alerts"):
                    new_status = st.selectbox(
                        "Update Status",
                        ["OPEN", "UNDER_INVESTIGATION", "FALSE_POSITIVE", "CLOSED"],
                        key=f"status_{alert['alert_id']}",
                        index=["OPEN", "UNDER_INVESTIGATION", "FALSE_POSITIVE", "CLOSED"].index(alert["status"])
                        if alert["status"] in ["OPEN", "UNDER_INVESTIGATION", "FALSE_POSITIVE", "CLOSED"]
                        else 0,
                    )
                    if st.button("Update Status", key=f"upd_{alert['alert_id']}"):
                        success, msg = update_alert_status(alert["alert_id"], new_status, st.session_state.username)
                        if success:
                            log_action(st.session_state.username, UPDATE_ALERT, msg)
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)

            with act2:
                if check_permission(st.session_state.role, "create_incidents") and alert["status"] != "CLOSED":
                    if st.button("🔥 Create Incident", key=f"inc_{alert['alert_id']}"):
                        success, result = create_incident(
                            alert["alert_id"],
                            alert["threat_type"],
                            alert["severity"],
                            alert.get("description", ""),
                            st.session_state.username,
                        )
                        if success:
                            log_action(st.session_state.username, CREATE_INCIDENT, f"Incident {result} from {alert['alert_id']}")
                            st.success(f"✅ Incident **{result}** created!")
                            st.rerun()
                        else:
                            st.error(result)


# ═══════════════════════════════════════════════════════════════════════════
# PAGE: INVESTIGATIONS
# ═══════════════════════════════════════════════════════════════════════════

def page_investigations():
    # Check if user has investigate or review permission
    has_investigate = check_permission(st.session_state.role, "investigate_alerts")
    has_review = check_permission(st.session_state.role, "review_investigations")

    if not has_investigate and not has_review:
        st.error("⛔ Access Denied")
        st.stop()

    st.markdown('<h2 class="section-header">🔍 Alert Investigation</h2>', unsafe_allow_html=True)

    # Select an alert to investigate
    alerts = get_alerts(limit=200)
    if not alerts:
        st.info("No alerts available for investigation.")
        return

    alert_options = {f"{a['alert_id']} — {a['threat_type']} ({a['status']})": a["alert_id"] for a in alerts}
    selected = st.selectbox("Select Alert to Investigate", list(alert_options.keys()))
    alert_id = alert_options[selected]
    alert = get_alert_by_id(alert_id)

    if alert:
        # Alert detail
        st.markdown(f"### {alert['alert_id']} — {alert['threat_type']}")
        col_d1, col_d2, col_d3 = st.columns(3)
        with col_d1:
            st.markdown(f"**Severity:** {severity_badge(alert['severity'])}", unsafe_allow_html=True)
        with col_d2:
            st.markdown(f"**Status:** {status_badge(alert['status'])}", unsafe_allow_html=True)
        with col_d3:
            st.markdown(f"**MITRE:** {alert.get('mitre_technique_id', 'N/A')} — {alert.get('mitre_technique_name', 'N/A')}")

        st.markdown(f"**Description:** {alert.get('description', 'N/A')}")
        st.markdown(f"**Source IP:** {alert.get('source_ip', 'N/A')} | **Affected User:** {alert.get('affected_user', 'N/A')}")
        st.markdown(f"**Timestamp:** {alert['timestamp']}")

        # ── Investigation Notes ─────────────────────────────
        st.markdown("---")
        st.markdown("#### 📝 Investigation Notes")

        notes = get_investigation_notes(alert_id)
        if notes:
            for note in notes:
                verdict_text = f" — **{note.get('verdict', '')}**" if note.get("verdict") else ""
                st.markdown(
                    f"🔹 **{note['analyst']}** ({note['created_at']}){verdict_text}:  \n"
                    f"> {note['note']}"
                )
        else:
            st.info("No investigation notes yet.")

        # ── Add note form ───────────────────────────────────
        if has_investigate:
            st.markdown("#### ➕ Add Investigation Note")
            with st.form(f"note_form_{alert_id}"):
                note_text = st.text_area("Investigation Notes", placeholder="Document your findings...")
                verdict = st.selectbox(
                    "Verdict",
                    ["— No verdict —", "TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_INVESTIGATION"],
                )
                submit_note = st.form_submit_button("Submit Note", use_container_width=True)

            if submit_note and note_text:
                v = verdict if verdict != "— No verdict —" else None
                success, msg = add_investigation_note(alert_id, st.session_state.username, note_text, v)
                if success:
                    log_action(
                        st.session_state.username,
                        INVESTIGATE_ALERT,
                        f"Note added to {alert_id}" + (f" verdict={v}" if v else ""),
                    )
                    st.success("✅ Investigation note added!")
                    st.rerun()
                else:
                    st.error(msg)


# ═══════════════════════════════════════════════════════════════════════════
# PAGE: INCIDENTS
# ═══════════════════════════════════════════════════════════════════════════

def page_incidents():
    has_view = check_permission(st.session_state.role, "view_all_incidents")
    has_create = check_permission(st.session_state.role, "create_incidents")

    if not has_view and not has_create:
        st.error("⛔ Access Denied")
        st.stop()

    st.markdown('<h2 class="section-header">🔥 Incident Management</h2>', unsafe_allow_html=True)

    # Filters
    fc1, fc2 = st.columns(2)
    with fc1:
        status_f = st.selectbox("Filter by Status", ["ALL", "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"])
    with fc2:
        severity_f = st.selectbox("Filter by Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="inc_sev")

    incidents = get_incidents(
        status_filter=status_f if status_f != "ALL" else None,
        severity_filter=severity_f if severity_f != "ALL" else None,
    )

    if not incidents:
        st.info("No incidents match your filters.")
        return

    st.caption(f"Showing {len(incidents)} incident(s)")

    for inc in incidents:
        with st.expander(
            f"{inc['incident_id']} — {inc['threat_type']} | {inc['severity']} | {inc['status']}",
            expanded=False,
        ):
            col_i1, col_i2 = st.columns(2)
            with col_i1:
                st.markdown(f"**Incident ID:** {inc['incident_id']}")
                st.markdown(f"**Alert ID:** {inc.get('alert_id', 'N/A')}")
                st.markdown(f"**Threat Type:** {inc['threat_type']}")
                st.markdown(f"**Severity:** {severity_badge(inc['severity'])}", unsafe_allow_html=True)
            with col_i2:
                st.markdown(f"**Status:** {status_badge(inc['status'])}", unsafe_allow_html=True)
                st.markdown(f"**Created By:** {inc['created_by']}")
                st.markdown(f"**Created At:** {inc['created_at']}")
                st.markdown(f"**Updated At:** {inc.get('updated_at', 'N/A') or 'N/A'}")

            st.markdown(f"**Description:** {inc.get('description', 'N/A')}")

            if inc.get("resolution_notes"):
                st.markdown(f"**Resolution Notes:** {inc['resolution_notes']}")

            # ── Timeline ──────────────────────────────────────
            timeline = get_incident_timeline(inc["incident_id"])
            if timeline:
                with st.expander("📜 Incident Timeline"):
                    for entry in timeline:
                        st.markdown(
                            f"🕐 **{entry['timestamp']}** — {entry['action']} by `{entry['username']}`  \n"
                            f"  _{entry.get('details', '')}_"
                        )

            # ── Status Update ─────────────────────────────────
            if check_permission(st.session_state.role, "close_incidents"):
                st.markdown("---")
                ucol1, ucol2 = st.columns(2)
                with ucol1:
                    new_status = st.selectbox(
                        "Update Status",
                        ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"],
                        key=f"inc_status_{inc['incident_id']}",
                    )
                with ucol2:
                    res_notes = st.text_input("Resolution Notes", key=f"inc_notes_{inc['incident_id']}")

                if st.button("Update Incident", key=f"inc_upd_{inc['incident_id']}"):
                    success, msg = update_incident_status(
                        inc["incident_id"],
                        new_status,
                        res_notes,
                        st.session_state.username,
                    )
                    if success:
                        action = CLOSE_INCIDENT if new_status == "CLOSED" else UPDATE_INCIDENT
                        log_action(st.session_state.username, action, msg)
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)


# ═══════════════════════════════════════════════════════════════════════════
# PAGE: REPORTS
# ═══════════════════════════════════════════════════════════════════════════

def page_reports():
    require_permission(st.session_state.role, "view_reports")
    st.markdown('<h2 class="section-header">📄 Report Generation</h2>', unsafe_allow_html=True)

    tab_gen, tab_view = st.tabs(["📝 Generate Report", "📂 View Reports"])

    with tab_gen:
        incidents = get_incidents(limit=200)
        if not incidents:
            st.info("No incidents available for report generation.")
            return

        inc_options = {f"{i['incident_id']} — {i['threat_type']} ({i['status']})": i["incident_id"] for i in incidents}
        selected = st.selectbox("Select Incident", list(inc_options.keys()))
        incident_id = inc_options[selected]

        if st.button("📄 Generate PDF Report", type="primary", use_container_width=True):
            try:
                filepath = generate_incident_report(incident_id)
                log_action(st.session_state.username, GENERATE_REPORT, f"Report generated for {incident_id}")
                st.success(f"✅ Report generated: `{os.path.basename(filepath)}`")

                # Provide download
                with open(filepath, "rb") as f:
                    st.download_button(
                        "⬇️ Download Report",
                        data=f.read(),
                        file_name=os.path.basename(filepath),
                        mime="application/pdf",
                        use_container_width=True,
                    )
            except Exception as e:
                st.error(f"Error generating report: {e}")

    with tab_view:
        reports = get_generated_reports()
        if reports:
            for r in reports:
                col_name, col_dl = st.columns([3, 1])
                with col_name:
                    st.markdown(
                        f"📄 **{r['filename']}** — {r['incident_id']} | Generated: {r['generated_at']}"
                    )
                with col_dl:
                    if os.path.exists(r["filepath"]):
                        with open(r["filepath"], "rb") as f:
                            st.download_button(
                                "⬇️",
                                data=f.read(),
                                file_name=r["filename"],
                                mime="application/pdf",
                                key=f"dl_{r['filename']}",
                            )
        else:
            st.info("No reports generated yet.")


# ═══════════════════════════════════════════════════════════════════════════
# PAGE: USER MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════

def page_user_management():
    require_permission(st.session_state.role, "create_users")
    st.markdown('<h2 class="section-header">👥 User Management</h2>', unsafe_allow_html=True)

    tab_list, tab_create = st.tabs(["👤 Manage Users", "➕ Create User"])

    with tab_list:
        users = get_all_users()
        if users:
            user_df = pd.DataFrame(users)
            st.dataframe(user_df, use_container_width=True)

            st.markdown("---")
            st.markdown("#### Modify User")

            user_options = [u["username"] for u in users]
            selected_user = st.selectbox("Select User", user_options)

            col_role, col_del = st.columns(2)

            with col_role:
                new_role = st.selectbox("New Role", ["ADMIN", "SOC_MANAGER", "SOC_ANALYST"], key="new_role")
                if st.button("Update Role"):
                    success, msg = update_user_role(selected_user, new_role)
                    if success:
                        log_action(st.session_state.username, UPDATE_ROLE, f"Updated {selected_user} to {new_role}")
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

            with col_del:
                st.markdown("<br>", unsafe_allow_html=True)
                if selected_user != st.session_state.username:
                    if st.button("🗑️ Delete User", type="secondary"):
                        success, msg = delete_user(selected_user)
                        if success:
                            log_action(st.session_state.username, AUDIT_DELETE_USER, f"Deleted user {selected_user}")
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)
                else:
                    st.warning("Cannot delete yourself.")
        else:
            st.info("No users found.")

    with tab_create:
        st.markdown("#### Create New User")
        with st.form("create_user_form"):
            new_username = st.text_input("Username", placeholder="Enter username")
            new_password = st.text_input("Password", type="password", placeholder="Min 8 chars, 1 upper, 1 digit, 1 special")
            new_user_role = st.selectbox("Role", ["SOC_ANALYST", "SOC_MANAGER", "ADMIN"])
            submitted = st.form_submit_button("Create User", use_container_width=True)

        if submitted:
            if not new_username or not new_password:
                st.error("All fields are required.")
            else:
                success, msg = create_user(new_username, new_password, new_user_role, st.session_state.username)
                if success:
                    log_action(
                        st.session_state.username,
                        AUDIT_CREATE_USER,
                        f"Created user {new_username} with role {new_user_role}",
                    )
                    st.success(f"✅ {msg}")
                    st.rerun()
                else:
                    st.error(msg)


# ═══════════════════════════════════════════════════════════════════════════
# PAGE: AUDIT LOGS
# ═══════════════════════════════════════════════════════════════════════════

def page_audit_logs():
    require_permission(st.session_state.role, "view_audit_logs")
    st.markdown('<h2 class="section-header">📋 Audit Trail</h2>', unsafe_allow_html=True)

    # Filters
    fc1, fc2, fc3, fc4 = st.columns(4)
    with fc1:
        user_filter = st.text_input("Filter by Username", placeholder="All users")
    with fc2:
        actions = get_audit_actions()
        action_options = ["ALL"] + actions
        action_filter = st.selectbox("Filter by Action", action_options)
    with fc3:
        start_date = st.date_input("Start Date", value=None)
    with fc4:
        end_date = st.date_input("End Date", value=None)

    logs = get_audit_logs(
        username_filter=user_filter if user_filter else None,
        action_filter=action_filter if action_filter != "ALL" else None,
        start_date=str(start_date) if start_date else None,
        end_date=str(end_date) if end_date else None,
        limit=500,
    )

    if logs:
        audit_df = pd.DataFrame(logs)
        display_cols = ["timestamp", "username", "action", "details", "ip_address"]
        available_cols = [c for c in display_cols if c in audit_df.columns]
        st.dataframe(audit_df[available_cols], use_container_width=True, height=600)
        st.caption(f"Showing {len(logs)} audit entries")
    else:
        st.info("No audit logs match your filters.")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ROUTER
# ═══════════════════════════════════════════════════════════════════════════

def main():
    if not st.session_state.logged_in:
        render_login()
        return

    render_sidebar()

    page_map = {
        "Dashboard": page_dashboard,
        "Upload Logs": page_upload_logs,
        "Alerts": page_alerts,
        "Investigations": page_investigations,
        "Incidents": page_incidents,
        "Reports": page_reports,
        "User Management": page_user_management,
        "Audit Logs": page_audit_logs,
    }

    current = st.session_state.current_page
    if current in page_map:
        page_map[current]()
    else:
        page_dashboard()


if __name__ == "__main__":
    main()
