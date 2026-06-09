"""
SOC Platform — Audit Logging Module
====================================
Provides an immutable audit trail for every significant action performed on
the platform.  All entries are written to the ``audit_logs`` table and are
never updated or deleted — they serve as a tamper-evident record for
compliance and forensic review.

Functions
---------
- log_action        : Record an auditable event.
- get_audit_logs    : Query the audit trail with optional filters.
- get_audit_actions : Return the set of distinct action types already logged.

Usage::

    from modules.audit import log_action, LOGIN
    log_action(username="admin", action=LOGIN, details="Successful login")
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from typing import Optional

# ---------------------------------------------------------------------------
# Database helper
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "database", "soc.db"
)


def _get_conn() -> sqlite3.Connection:
    """Return a new SQLite connection with WAL mode & foreign keys enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Action constants — use these instead of magic strings throughout the app
# ---------------------------------------------------------------------------
LOGIN: str = "LOGIN"
LOGOUT: str = "LOGOUT"
FAILED_LOGIN: str = "FAILED_LOGIN"
UPLOAD_LOG: str = "UPLOAD_LOG"
RUN_DETECTION: str = "RUN_DETECTION"
CREATE_ALERT: str = "CREATE_ALERT"
INVESTIGATE_ALERT: str = "INVESTIGATE_ALERT"
UPDATE_ALERT: str = "UPDATE_ALERT"
CREATE_INCIDENT: str = "CREATE_INCIDENT"
UPDATE_INCIDENT: str = "UPDATE_INCIDENT"
CLOSE_INCIDENT: str = "CLOSE_INCIDENT"
CREATE_USER: str = "CREATE_USER"
DELETE_USER: str = "DELETE_USER"
UPDATE_ROLE: str = "UPDATE_ROLE"
GENERATE_REPORT: str = "GENERATE_REPORT"
UNAUTHORIZED_ACCESS: str = "UNAUTHORIZED_ACCESS"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def log_action(
    username: str,
    action: str,
    details: str = "",
    ip_address: str = "",
) -> None:
    """Record an auditable event in the ``audit_logs`` table.

    Parameters
    ----------
    username : str
        The user who performed the action.
    action : str
        One of the module-level action constants (e.g. ``LOGIN``).
    details : str, optional
        Free-text description providing additional context.
    ip_address : str, optional
        Source IP address of the request, when available.

    Raises
    ------
    sqlite3.Error
        Propagated if the database write fails — callers should handle
        gracefully so that a logging failure never blocks a user action.
    """
    conn = _get_conn()
    try:
        conn.execute(
            """
            INSERT INTO audit_logs (username, action, details, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username.strip(),
                action.strip(),
                details,
                ip_address,
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        conn.commit()
    except sqlite3.Error:
        # Re-raise so the caller can decide how to handle it
        raise
    finally:
        conn.close()


def get_audit_logs(
    username_filter: Optional[str] = None,
    action_filter: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100,
) -> list[dict]:
    """Query the audit trail with optional filters.

    Parameters
    ----------
    username_filter : str, optional
        Exact-match filter on the ``username`` column.
    action_filter : str, optional
        Exact-match filter on the ``action`` column.
    start_date : str, optional
        Inclusive lower bound in ``YYYY-MM-DD`` or ``YYYY-MM-DD HH:MM:SS``
        format.
    end_date : str, optional
        Inclusive upper bound in ``YYYY-MM-DD`` or ``YYYY-MM-DD HH:MM:SS``
        format.
    limit : int
        Maximum number of rows to return (default 100).

    Returns
    -------
    list[dict]
        Each dict mirrors a row in the ``audit_logs`` table with keys:
        ``id``, ``username``, ``action``, ``details``, ``ip_address``,
        ``timestamp``.
    """
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params: list = []

    if username_filter:
        query += " AND username = ?"
        params.append(username_filter.strip())

    if action_filter:
        query += " AND action = ?"
        params.append(action_filter.strip())

    if start_date:
        query += " AND timestamp >= ?"
        params.append(start_date.strip())

    if end_date:
        query += " AND timestamp <= ?"
        params.append(end_date.strip())

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    conn = _get_conn()
    try:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_audit_actions() -> list[str]:
    """Return the distinct action values currently stored in ``audit_logs``.

    Returns
    -------
    list[str]
        Sorted list of unique action strings (e.g. ``["LOGIN", "LOGOUT"]``).
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT DISTINCT action FROM audit_logs ORDER BY action"
        ).fetchall()
        return [row["action"] for row in rows]
    finally:
        conn.close()
