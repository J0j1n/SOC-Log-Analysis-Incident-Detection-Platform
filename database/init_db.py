"""
SOC Platform — Database Initialization
=======================================
Creates all tables and seeds the default ADMIN user.

Tables created:
    - users              : Platform user accounts with roles
    - uploaded_logs       : Parsed & normalized security log events
    - alerts              : Generated security alerts with MITRE mapping
    - incidents           : Incident records linked to confirmed alerts
    - investigation_notes : Analyst notes attached to alerts
    - audit_logs          : Immutable audit trail of all platform actions

Usage:
    python database/init_db.py
"""

import sqlite3
import os
import sys

# ---------------------------------------------------------------------------
# Resolve the path to soc.db relative to *this* file so the script works
# regardless of the caller's working directory.
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "soc.db")

# We need bcrypt for seeding the admin user — add the project root to
# sys.path so that `modules.auth` can be imported if needed, but here we
# call bcrypt directly to avoid a circular import.
PROJECT_ROOT = os.path.dirname(BASE_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def get_connection():
    """Return a new SQLite connection with WAL mode & foreign keys enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.row_factory = sqlite3.Row
    return conn


# ── Schema Definitions ─────────────────────────────────────────────────────

SCHEMA_SQL = """
-- ========================================================================
-- USERS
-- ========================================================================
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK(role IN ('ADMIN', 'SOC_MANAGER', 'SOC_ANALYST')),
    created_at    TEXT    DEFAULT (datetime('now')),
    created_by    TEXT    DEFAULT 'SYSTEM',
    is_active     INTEGER DEFAULT 1
);

-- ========================================================================
-- UPLOADED LOGS  (normalised security events)
-- ========================================================================
CREATE TABLE IF NOT EXISTS uploaded_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    username      TEXT,
    source_ip     TEXT,
    raw_log       TEXT,
    log_source    TEXT    DEFAULT 'AUTH',
    uploaded_by   TEXT    NOT NULL,
    uploaded_at   TEXT    DEFAULT (datetime('now'))
);

-- ========================================================================
-- ALERTS
-- ========================================================================
CREATE TABLE IF NOT EXISTS alerts (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id             TEXT    UNIQUE NOT NULL,
    threat_type          TEXT    NOT NULL,
    severity             TEXT    NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    source_ip            TEXT,
    affected_user        TEXT,
    description          TEXT,
    mitre_tactic         TEXT,
    mitre_technique_id   TEXT,
    mitre_technique_name TEXT,
    timestamp            TEXT    DEFAULT (datetime('now')),
    status               TEXT    DEFAULT 'OPEN'
                                CHECK(status IN ('OPEN', 'UNDER_INVESTIGATION',
                                                  'FALSE_POSITIVE', 'CLOSED')),
    assigned_to          TEXT
);

-- ========================================================================
-- INCIDENTS
-- ========================================================================
CREATE TABLE IF NOT EXISTS incidents (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id      TEXT    UNIQUE NOT NULL,
    alert_id         TEXT    REFERENCES alerts(alert_id),
    threat_type      TEXT    NOT NULL,
    severity         TEXT    NOT NULL,
    description      TEXT,
    status           TEXT    DEFAULT 'OPEN'
                            CHECK(status IN ('OPEN', 'INVESTIGATING', 'CONTAINED',
                                              'RESOLVED', 'CLOSED')),
    created_by       TEXT    NOT NULL,
    created_at       TEXT    DEFAULT (datetime('now')),
    updated_at       TEXT,
    resolution_notes TEXT
);

-- ========================================================================
-- INVESTIGATION NOTES
-- ========================================================================
CREATE TABLE IF NOT EXISTS investigation_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   TEXT    NOT NULL,
    analyst    TEXT    NOT NULL,
    note       TEXT    NOT NULL,
    verdict    TEXT    CHECK(verdict IN ('TRUE_POSITIVE', 'FALSE_POSITIVE',
                                         'NEEDS_INVESTIGATION')),
    created_at TEXT    DEFAULT (datetime('now'))
);

-- ========================================================================
-- AUDIT LOGS  (immutable action trail)
-- ========================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    details    TEXT,
    ip_address TEXT,
    timestamp  TEXT    DEFAULT (datetime('now'))
);
"""

# ── Indexes for common query patterns ──────────────────────────────────────

INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_uploaded_logs_timestamp  ON uploaded_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_uploaded_logs_event_type ON uploaded_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_uploaded_logs_source_ip  ON uploaded_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_status            ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity          ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp         ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_incidents_status         ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_username      ON audit_logs(username);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp     ON audit_logs(timestamp);
"""


def _seed_admin(conn):
    """Insert the default ADMIN user if it doesn't already exist."""
    import bcrypt

    cursor = conn.execute("SELECT 1 FROM users WHERE username = ?", ("admin",))
    if cursor.fetchone() is not None:
        return  # Already seeded

    password = "Admin@123"
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn.execute(
        """
        INSERT INTO users (username, password_hash, role, created_by)
        VALUES (?, ?, 'ADMIN', 'SYSTEM')
        """,
        ("admin", password_hash),
    )
    conn.commit()
    print("[+] Default ADMIN user created  (username: admin / password: Admin@123)")


def initialize_database():
    """Create all tables, indexes, and seed data."""
    print(f"[*] Initializing database at {DB_PATH}")

    conn = get_connection()
    try:
        conn.executescript(SCHEMA_SQL)
        conn.executescript(INDEXES_SQL)
        _seed_admin(conn)
        print("[+] Database initialized successfully.")
    finally:
        conn.close()


# ── CLI entry point ────────────────────────────────────────────────────────
if __name__ == "__main__":
    initialize_database()
