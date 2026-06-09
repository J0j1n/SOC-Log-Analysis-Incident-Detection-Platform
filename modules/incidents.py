"""
SOC Platform — Incident Management Module
==========================================
Provides full lifecycle management for security incidents:

- Create incidents linked to confirmed alerts
- Query / filter incidents by status and severity
- Enforce validated status transitions (OPEN → INVESTIGATING → … → CLOSED)
- Collect resolution notes on closure
- Aggregate incident statistics for dashboards
- Build chronological timelines from the audit log

All functions are self-contained and use the shared DB connection pattern.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
DB_PATH: str = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "database", "soc.db"
)

# Allowed status transitions — keys are current statuses, values are the set
# of statuses they may transition to.  This prevents nonsensical jumps such
# as CLOSED → OPEN.
_VALID_TRANSITIONS: dict[str, set[str]] = {
    "OPEN":          {"INVESTIGATING", "CLOSED"},
    "INVESTIGATING": {"CONTAINED", "RESOLVED", "CLOSED"},
    "CONTAINED":     {"RESOLVED", "CLOSED"},
    "RESOLVED":      {"CLOSED"},
    "CLOSED":        set(),          # terminal — no further transitions
}


def _get_conn() -> sqlite3.Connection:
    """Return a new SQLite connection with WAL mode & foreign keys enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
    """Convert a sqlite3.Row to a plain dict, returning *None* for *None*."""
    return dict(row) if row is not None else None


def _log_audit(
    conn: sqlite3.Connection,
    username: str,
    action: str,
    details: str,
) -> None:
    """Insert a record into *audit_logs* inside the given transaction."""
    conn.execute(
        """
        INSERT INTO audit_logs (username, action, details, ip_address, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, action, details, "127.0.0.1", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
    )


# ---------------------------------------------------------------------------
# 1. generate_incident_id
# ---------------------------------------------------------------------------

def generate_incident_id() -> str:
    """Return the next sequential incident ID (e.g. ``INC001``, ``INC002``).

    Reads the current maximum ``incident_id`` from the *incidents* table and
    increments the numeric suffix by one.  If no incidents exist yet, the
    first ID will be ``INC001``.

    Returns:
        str: The new incident ID string.
    """
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT incident_id FROM incidents ORDER BY id DESC LIMIT 1"
        ).fetchone()

        if row is None:
            return "INC001"

        # Extract numeric portion, increment, and zero-pad to at least 3 digits
        last_id: str = row["incident_id"]
        numeric_part = int(last_id.replace("INC", ""))
        return f"INC{numeric_part + 1:03d}"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 2. create_incident
# ---------------------------------------------------------------------------

def create_incident(
    alert_id: str,
    threat_type: str,
    severity: str,
    description: str,
    created_by: str,
) -> tuple[bool, str]:
    """Create a new incident linked to *alert_id*.

    The linked alert's status is automatically updated to
    ``UNDER_INVESTIGATION`` so that the alert pipeline reflects the
    escalation.

    Args:
        alert_id:    The alert being escalated (e.g. ``ALT001``).
        threat_type: High-level threat category (e.g. ``Brute Force``).
        severity:    One of ``LOW``, ``MEDIUM``, ``HIGH``, ``CRITICAL``.
        description: Free-text description of the incident.
        created_by:  Username of the analyst creating the incident.

    Returns:
        A ``(success, message)`` tuple.  On success, *message* is the new
        incident ID; on failure it contains an error description.
    """
    conn = _get_conn()
    try:
        # Verify the alert exists
        alert = conn.execute(
            "SELECT alert_id FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if alert is None:
            return False, f"Alert '{alert_id}' does not exist."

        # Verify severity value
        valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if severity.upper() not in valid_severities:
            return False, f"Invalid severity '{severity}'. Must be one of {valid_severities}."

        incident_id = generate_incident_id()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        conn.execute(
            """
            INSERT INTO incidents
                (incident_id, alert_id, threat_type, severity,
                 description, status, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?)
            """,
            (incident_id, alert_id, threat_type, severity.upper(),
             description, created_by, now, now),
        )

        # Escalate the linked alert
        conn.execute(
            "UPDATE alerts SET status = 'UNDER_INVESTIGATION' WHERE alert_id = ?",
            (alert_id,),
        )

        _log_audit(
            conn,
            created_by,
            "CREATE_INCIDENT",
            f"Created incident {incident_id} from alert {alert_id} | "
            f"severity={severity.upper()} | threat={threat_type}",
        )

        conn.commit()
        return True, incident_id

    except sqlite3.IntegrityError as exc:
        conn.rollback()
        return False, f"Database integrity error: {exc}"
    except sqlite3.Error as exc:
        conn.rollback()
        return False, f"Database error: {exc}"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 3. get_incidents
# ---------------------------------------------------------------------------

def get_incidents(
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    limit: int = 100,
) -> list[dict]:
    """Return a list of incidents, newest first.

    Args:
        status_filter:   Optional status to filter by (e.g. ``OPEN``).
        severity_filter: Optional severity to filter by (e.g. ``CRITICAL``).
        limit:           Maximum number of rows to return (default 100).

    Returns:
        A list of incident dicts ordered by ``created_at DESC``.
    """
    conn = _get_conn()
    try:
        query = "SELECT * FROM incidents WHERE 1=1"
        params: list = []

        if status_filter:
            query += " AND status = ?"
            params.append(status_filter.upper())

        if severity_filter:
            query += " AND severity = ?"
            params.append(severity_filter.upper())

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 4. get_incident_by_id
# ---------------------------------------------------------------------------

def get_incident_by_id(incident_id: str) -> dict | None:
    """Fetch a single incident by its ID.

    Args:
        incident_id: The incident identifier (e.g. ``INC001``).

    Returns:
        An incident dict, or *None* if not found.
    """
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id.upper(),),
        ).fetchone()
        return _row_to_dict(row)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 5. update_incident_status
# ---------------------------------------------------------------------------

def update_incident_status(
    incident_id: str,
    new_status: str,
    resolution_notes: str = "",
    updated_by: str = "",
) -> tuple[bool, str]:
    """Transition an incident to *new_status* with validation.

    Valid transitions::

        OPEN          → INVESTIGATING, CLOSED
        INVESTIGATING → CONTAINED, RESOLVED, CLOSED
        CONTAINED     → RESOLVED, CLOSED
        RESOLVED      → CLOSED
        CLOSED        → (none — terminal state)

    If *new_status* is ``CLOSED`` or ``RESOLVED``, *resolution_notes* are
    stored.  An audit-log entry is written for every successful transition.

    Args:
        incident_id:      The incident to update.
        new_status:        Target status.
        resolution_notes:  Notes explaining the resolution (used for
                           CLOSED / RESOLVED).
        updated_by:        Username performing the update.

    Returns:
        A ``(success, message)`` tuple.
    """
    new_status = new_status.upper()
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id.upper(),),
        ).fetchone()

        if row is None:
            return False, f"Incident '{incident_id}' not found."

        current_status: str = row["status"]

        # Validate the transition
        allowed = _VALID_TRANSITIONS.get(current_status, set())
        if new_status not in allowed:
            return (
                False,
                f"Invalid status transition: {current_status} → {new_status}. "
                f"Allowed targets: {sorted(allowed) if allowed else 'none (terminal state)'}.",
            )

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        if new_status in {"CLOSED", "RESOLVED"}:
            conn.execute(
                """
                UPDATE incidents
                   SET status           = ?,
                       resolution_notes = ?,
                       updated_at       = ?
                 WHERE incident_id      = ?
                """,
                (new_status, resolution_notes, now, incident_id.upper()),
            )
        else:
            conn.execute(
                """
                UPDATE incidents
                   SET status      = ?,
                       updated_at  = ?
                 WHERE incident_id = ?
                """,
                (new_status, now, incident_id.upper()),
            )

        _log_audit(
            conn,
            updated_by or "SYSTEM",
            "UPDATE_INCIDENT_STATUS",
            f"Incident {incident_id} status changed: {current_status} → {new_status}"
            + (f" | resolution_notes={resolution_notes}" if resolution_notes else ""),
        )

        conn.commit()
        return True, f"Incident {incident_id} updated to {new_status}."

    except sqlite3.Error as exc:
        conn.rollback()
        return False, f"Database error: {exc}"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 6. get_incident_stats
# ---------------------------------------------------------------------------

def get_incident_stats() -> dict:
    """Return aggregate incident counts keyed by status.

    Returns:
        A dict with keys: ``total``, ``open``, ``investigating``,
        ``contained``, ``resolved``, ``closed``.
    """
    conn = _get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) AS cnt FROM incidents").fetchone()["cnt"]

        stats: dict[str, int] = {
            "total":         total,
            "open":          0,
            "investigating": 0,
            "contained":     0,
            "resolved":      0,
            "closed":        0,
        }

        rows = conn.execute(
            "SELECT status, COUNT(*) AS cnt FROM incidents GROUP BY status"
        ).fetchall()

        for row in rows:
            key = row["status"].lower()
            if key in stats:
                stats[key] = row["cnt"]

        return stats
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 7. get_incident_timeline
# ---------------------------------------------------------------------------

def get_incident_timeline(incident_id: str) -> list[dict]:
    """Build a chronological timeline for *incident_id* from audit logs.

    Searches the ``details`` column of *audit_logs* for any mention of
    the given incident ID and returns matching entries sorted by timestamp
    ascending (oldest first).

    Args:
        incident_id: The incident identifier to search for.

    Returns:
        A list of audit-log dicts in chronological order.
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT id, username, action, details, ip_address, timestamp
              FROM audit_logs
             WHERE details LIKE ?
             ORDER BY timestamp ASC
            """,
            (f"%{incident_id.upper()}%",),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
