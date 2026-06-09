"""
SOC Platform — Alert Management
================================
Provides alert lifecycle management: creation (with auto-incremented IDs),
deduplication against open alerts, status transitions, statistics, and
investigation-note tracking.

All database access goes through a local ``_get_conn()`` helper that
enforces WAL journaling and foreign keys on every connection.

Usage::

    from modules.alerts import create_alerts_from_detections, get_alerts
    from modules.detector import run_all_detections

    new_count = create_alerts_from_detections(run_all_detections(logs_df))
    open_alerts = get_alerts(status_filter="OPEN")
"""

from __future__ import annotations

import logging
import os
import sqlite3
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "database", "soc.db"
)

_VALID_STATUSES = {"OPEN", "UNDER_INVESTIGATION", "FALSE_POSITIVE", "CLOSED"}
_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_VALID_VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_INVESTIGATION"}


def _get_conn() -> sqlite3.Connection:
    """Return a new SQLite connection with WAL mode & foreign keys enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    """Convert a :class:`sqlite3.Row` to a plain dict (or *None*)."""
    if row is None:
        return None
    return dict(row)


# ---------------------------------------------------------------------------
# 1. Alert-ID generation
# ---------------------------------------------------------------------------


def generate_alert_id() -> str:
    """Generate the next sequential alert ID (``ALT001``, ``ALT002``, …).

    Queries the current maximum ``alert_id`` in the ``alerts`` table and
    increments the numeric suffix by one.  If no alerts exist yet the
    function returns ``ALT001``.

    Returns
    -------
    str
        A zero-padded alert identifier, e.g. ``"ALT001"``.
    """
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT alert_id FROM alerts ORDER BY id DESC LIMIT 1"
        ).fetchone()

        if row is None:
            return "ALT001"

        last_id: str = row["alert_id"]
        # Strip the "ALT" prefix, parse the integer, and increment
        numeric_part = int(last_id.replace("ALT", ""))
        return f"ALT{numeric_part + 1:03d}"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 2. Single-alert creation
# ---------------------------------------------------------------------------


def create_alert(
    threat_type: str,
    severity: str,
    source_ip: str,
    affected_user: str,
    description: str,
    mitre_tactic: str,
    mitre_technique_id: str,
    mitre_technique_name: str,
) -> str:
    """Insert a new alert into the ``alerts`` table.

    Parameters
    ----------
    threat_type:
        Category of threat (e.g. ``"Brute Force"``).
    severity:
        One of LOW, MEDIUM, HIGH, CRITICAL.
    source_ip:
        Originating IP address.
    affected_user:
        Targeted user(s), comma-separated if multiple.
    description:
        Free-text description of the alert.
    mitre_tactic:
        MITRE ATT&CK tactic name.
    mitre_technique_id:
        MITRE technique ID (e.g. ``"T1110"``).
    mitre_technique_name:
        MITRE technique name (e.g. ``"Brute Force"``).

    Returns
    -------
    str
        The generated ``alert_id`` (e.g. ``"ALT005"``).

    Raises
    ------
    ValueError
        If *severity* is not a recognised value.
    """
    severity = severity.upper()
    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. Must be one of {_VALID_SEVERITIES}."
        )

    alert_id = generate_alert_id()
    conn = _get_conn()
    try:
        conn.execute(
            """
            INSERT INTO alerts (
                alert_id, threat_type, severity, source_ip,
                affected_user, description, mitre_tactic,
                mitre_technique_id, mitre_technique_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                threat_type,
                severity,
                source_ip,
                affected_user,
                description,
                mitre_tactic,
                mitre_technique_id,
                mitre_technique_name,
            ),
        )
        conn.commit()
        logger.info("Alert %s created: %s [%s]", alert_id, threat_type, severity)
        return alert_id
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        logger.error("Failed to create alert %s: %s", alert_id, exc)
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 3. Batch creation with deduplication
# ---------------------------------------------------------------------------


def _is_duplicate(
    conn: sqlite3.Connection,
    threat_type: str,
    source_ip: str,
    affected_user: str,
) -> bool:
    """Check whether an OPEN alert with matching fields already exists."""
    row = conn.execute(
        """
        SELECT 1 FROM alerts
        WHERE threat_type   = ?
          AND source_ip     = ?
          AND affected_user = ?
          AND status        = 'OPEN'
        LIMIT 1
        """,
        (threat_type, source_ip, affected_user),
    ).fetchone()
    return row is not None


def create_alerts_from_detections(detections: list[dict]) -> int:
    """Persist detection results as alerts, skipping duplicates.

    An alert is considered a **duplicate** when an ``OPEN`` alert with the
    same ``threat_type``, ``source_ip``, and ``affected_user`` already
    exists in the database.

    Parameters
    ----------
    detections:
        List of alert dicts as produced by the detection engine.

    Returns
    -------
    int
        Number of *new* alerts actually created.
    """
    if not detections:
        return 0

    created_count = 0
    conn = _get_conn()
    try:
        for det in detections:
            threat_type = det["threat_type"]
            source_ip = det.get("source_ip", "")
            affected_user = det.get("affected_user", "")

            if _is_duplicate(conn, threat_type, source_ip, affected_user):
                logger.debug(
                    "Skipping duplicate alert: %s / %s / %s",
                    threat_type,
                    source_ip,
                    affected_user,
                )
                continue

            alert_id = generate_alert_id()
            conn.execute(
                """
                INSERT INTO alerts (
                    alert_id, threat_type, severity, source_ip,
                    affected_user, description, mitre_tactic,
                    mitre_technique_id, mitre_technique_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    threat_type,
                    det["severity"],
                    source_ip,
                    affected_user,
                    det.get("description", ""),
                    det.get("mitre_tactic", ""),
                    det.get("mitre_technique_id", ""),
                    det.get("mitre_technique_name", ""),
                ),
            )
            created_count += 1
            logger.info("Alert %s created from detection: %s", alert_id, threat_type)

        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("Error during batch alert creation — rolled back.")
        raise
    finally:
        conn.close()

    logger.info(
        "Batch complete: %d new alert(s) created from %d detection(s).",
        created_count,
        len(detections),
    )
    return created_count


# ---------------------------------------------------------------------------
# 4. Query helpers
# ---------------------------------------------------------------------------


def get_alerts(
    status_filter: str | None = None,
    severity_filter: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Retrieve alerts with optional status and severity filters.

    Parameters
    ----------
    status_filter:
        If provided, only return alerts with this status
        (``OPEN``, ``UNDER_INVESTIGATION``, ``FALSE_POSITIVE``, ``CLOSED``).
    severity_filter:
        If provided, only return alerts with this severity
        (``LOW``, ``MEDIUM``, ``HIGH``, ``CRITICAL``).
    limit:
        Maximum number of rows to return (default 100).

    Returns
    -------
    list[dict]
        Alert rows ordered by ``timestamp DESC``.
    """
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list[Any] = []

    if status_filter is not None:
        status_filter = status_filter.upper()
        if status_filter not in _VALID_STATUSES:
            logger.warning("Invalid status filter '%s' — ignoring.", status_filter)
        else:
            query += " AND status = ?"
            params.append(status_filter)

    if severity_filter is not None:
        severity_filter = severity_filter.upper()
        if severity_filter not in _VALID_SEVERITIES:
            logger.warning("Invalid severity filter '%s' — ignoring.", severity_filter)
        else:
            query += " AND severity = ?"
            params.append(severity_filter)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    conn = _get_conn()
    try:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 5. Single-alert lookup
# ---------------------------------------------------------------------------


def get_alert_by_id(alert_id: str) -> dict | None:
    """Return a single alert by its ``alert_id``, or *None* if not found.

    Parameters
    ----------
    alert_id:
        The unique alert identifier (e.g. ``"ALT003"``).

    Returns
    -------
    dict | None
    """
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        return _row_to_dict(row)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 6. Status update
# ---------------------------------------------------------------------------


def update_alert_status(
    alert_id: str,
    new_status: str,
    analyst: str,
) -> tuple[bool, str]:
    """Transition an alert to a new status.

    Parameters
    ----------
    alert_id:
        The alert to update.
    new_status:
        Target status (must be one of ``OPEN``, ``UNDER_INVESTIGATION``,
        ``FALSE_POSITIVE``, ``CLOSED``).
    analyst:
        Username of the analyst performing the action (used for the
        ``assigned_to`` field when moving to ``UNDER_INVESTIGATION``).

    Returns
    -------
    tuple[bool, str]
        ``(True, message)`` on success, ``(False, message)`` on failure.
    """
    new_status = new_status.upper()
    if new_status not in _VALID_STATUSES:
        return False, (
            f"Invalid status '{new_status}'. "
            f"Must be one of: {', '.join(sorted(_VALID_STATUSES))}."
        )

    conn = _get_conn()
    try:
        existing = conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()

        if existing is None:
            return False, f"Alert '{alert_id}' not found."

        current_status = existing["status"]
        if current_status == new_status:
            return False, (
                f"Alert '{alert_id}' is already in status '{new_status}'."
            )

        update_fields = "status = ?"
        params: list[Any] = [new_status]

        # Auto-assign analyst when moving to UNDER_INVESTIGATION
        if new_status == "UNDER_INVESTIGATION":
            update_fields += ", assigned_to = ?"
            params.append(analyst)

        params.append(alert_id)
        conn.execute(
            f"UPDATE alerts SET {update_fields} WHERE alert_id = ?",
            params,
        )
        conn.commit()

        msg = (
            f"Alert '{alert_id}' status updated from "
            f"'{current_status}' to '{new_status}' by {analyst}."
        )
        logger.info(msg)
        return True, msg
    except Exception as exc:
        conn.rollback()
        logger.exception("Failed to update alert status for %s", alert_id)
        return False, f"Database error: {exc}"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 7. Statistics
# ---------------------------------------------------------------------------


def get_alert_stats() -> dict[str, int]:
    """Return aggregate alert counts grouped by status and severity.

    Returns
    -------
    dict[str, int]
        Keys: ``total``, ``open``, ``under_investigation``,
        ``false_positive``, ``closed``, ``critical``, ``high``,
        ``medium``, ``low``.
    """
    conn = _get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]

        status_counts = conn.execute(
            """
            SELECT status, COUNT(*) AS c
            FROM alerts
            GROUP BY status
            """
        ).fetchall()
        status_map = {row["status"]: row["c"] for row in status_counts}

        severity_counts = conn.execute(
            """
            SELECT severity, COUNT(*) AS c
            FROM alerts
            GROUP BY severity
            """
        ).fetchall()
        severity_map = {row["severity"]: row["c"] for row in severity_counts}

        return {
            "total": total,
            "open": status_map.get("OPEN", 0),
            "under_investigation": status_map.get("UNDER_INVESTIGATION", 0),
            "false_positive": status_map.get("FALSE_POSITIVE", 0),
            "closed": status_map.get("CLOSED", 0),
            "critical": severity_map.get("CRITICAL", 0),
            "high": severity_map.get("HIGH", 0),
            "medium": severity_map.get("MEDIUM", 0),
            "low": severity_map.get("LOW", 0),
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 8. Investigation notes — create
# ---------------------------------------------------------------------------


def add_investigation_note(
    alert_id: str,
    analyst: str,
    note: str,
    verdict: str | None = None,
) -> tuple[bool, str]:
    """Attach an investigation note to an alert.

    Parameters
    ----------
    alert_id:
        The alert this note relates to.
    analyst:
        Username of the authoring analyst.
    note:
        Free-text note content.
    verdict:
        Optional verdict — must be ``TRUE_POSITIVE``,
        ``FALSE_POSITIVE``, or ``NEEDS_INVESTIGATION``.

    Returns
    -------
    tuple[bool, str]
        ``(True, message)`` on success, ``(False, message)`` on failure.
    """
    if verdict is not None:
        verdict = verdict.upper()
        if verdict not in _VALID_VERDICTS:
            return False, (
                f"Invalid verdict '{verdict}'. "
                f"Must be one of: {', '.join(sorted(_VALID_VERDICTS))}."
            )

    # Verify the alert exists
    conn = _get_conn()
    try:
        existing = conn.execute(
            "SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()

        if existing is None:
            return False, f"Alert '{alert_id}' not found."

        conn.execute(
            """
            INSERT INTO investigation_notes (alert_id, analyst, note, verdict)
            VALUES (?, ?, ?, ?)
            """,
            (alert_id, analyst, note, verdict),
        )
        conn.commit()

        msg = (
            f"Investigation note added to alert '{alert_id}' by {analyst}"
            + (f" with verdict '{verdict}'." if verdict else ".")
        )
        logger.info(msg)
        return True, msg
    except Exception as exc:
        conn.rollback()
        logger.exception("Failed to add investigation note for %s", alert_id)
        return False, f"Database error: {exc}"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 9. Investigation notes — read
# ---------------------------------------------------------------------------


def get_investigation_notes(alert_id: str) -> list[dict]:
    """Retrieve all investigation notes for an alert.

    Parameters
    ----------
    alert_id:
        The alert whose notes to retrieve.

    Returns
    -------
    list[dict]
        Notes ordered by ``created_at DESC``.
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT * FROM investigation_notes
            WHERE alert_id = ?
            ORDER BY created_at DESC
            """,
            (alert_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
