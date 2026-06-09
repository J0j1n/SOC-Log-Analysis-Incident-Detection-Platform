"""
SOC Platform — Log Parser Module
=================================
Validates, parses, normalises, and stores authentication log files.

Supported formats
-----------------
- **.txt**  — space-delimited lines:
  ``YYYY-MM-DD HH:MM:SS EVENT_TYPE username [source_ip]``
- **.csv**  — comma-separated with header row:
  ``timestamp,event_type,username,source_ip``

Public API
----------
- ``validate_file``      — pre-flight checks (extension + size).
- ``parse_txt_log``      — parse raw TXT content → list[dict].
- ``parse_csv_log``      — parse raw CSV content → list[dict].
- ``normalize_event``    — clean / validate a single event dict.
- ``parse_log_file``     — orchestrator: detect format → parse → normalise.
- ``store_parsed_logs``  — bulk-insert events into ``uploaded_logs``.
- ``get_uploaded_logs``  — retrieve stored logs ordered by timestamp.

Usage::

    from modules.parser import parse_log_file, store_parsed_logs

    events, errors = parse_log_file("auth_logs.txt", raw_content)
    if events:
        count = store_parsed_logs(events, uploaded_by="analyst1")
"""

from __future__ import annotations

import csv
import io
import logging
import os
import re
import sqlite3
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database helper
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "database", "soc.db"
)


def _get_conn() -> sqlite3.Connection:
    """Return a new SQLite connection with WAL journal mode and FK enforcement."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ALLOWED_EXTENSIONS: set[str] = {".txt", ".csv"}
MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10 MB

# Regex for TXT log lines:
#   Group 1 — timestamp  (YYYY-MM-DD HH:MM:SS)
#   Group 2 — event_type
#   Group 3 — username
#   Group 4 — source_ip  (optional, may be empty string)
_TXT_LINE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s*(\S*)"
)

_TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"


# ═══════════════════════════════════════════════════════════════════════════
# 1. File Validation
# ═══════════════════════════════════════════════════════════════════════════
def validate_file(filename: str, file_size: int) -> tuple[bool, str]:
    """Check that *filename* has an allowed extension and *file_size* is within limits.

    Parameters
    ----------
    filename : str
        Name (or path) of the file to validate.
    file_size : int
        Size of the file in bytes.

    Returns
    -------
    tuple[bool, str]
        ``(True, "")`` on success, or ``(False, "<reason>")`` on failure.
    """
    if not filename:
        return False, "Filename is empty."

    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    if ext not in ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        return False, (
            f"Unsupported file extension '{ext}'. "
            f"Allowed extensions: {allowed}"
        )

    if file_size <= 0:
        return False, "File is empty (0 bytes)."

    if file_size > MAX_FILE_SIZE:
        max_mb = MAX_FILE_SIZE / (1024 * 1024)
        return False, (
            f"File size ({file_size:,} bytes) exceeds the "
            f"{max_mb:.0f} MB limit."
        )

    return True, ""


# ═══════════════════════════════════════════════════════════════════════════
# 2. TXT Parser
# ═══════════════════════════════════════════════════════════════════════════
def parse_txt_log(content: str) -> list[dict[str, str]]:
    """Parse authentication log lines from plain-text content.

    Expected format per line::

        YYYY-MM-DD HH:MM:SS EVENT_TYPE username [source_ip]

    Lines that do not match the pattern are silently skipped (callers
    should use :func:`parse_log_file` if per-line error tracking is needed).

    Parameters
    ----------
    content : str
        Raw text content of the log file.

    Returns
    -------
    list[dict[str, str]]
        Each dict contains: ``timestamp``, ``event_type``, ``username``,
        ``source_ip``, and ``raw_log``.
    """
    events: list[dict[str, str]] = []

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue  # skip blanks / comments

        match = _TXT_LINE_RE.match(stripped)
        if match:
            events.append(
                {
                    "timestamp": match.group(1).strip(),
                    "event_type": match.group(2).strip(),
                    "username": match.group(3).strip(),
                    "source_ip": match.group(4).strip() if match.group(4) else "",
                    "raw_log": stripped,
                }
            )

    return events


# ═══════════════════════════════════════════════════════════════════════════
# 3. CSV Parser
# ═══════════════════════════════════════════════════════════════════════════
def parse_csv_log(content: str) -> list[dict[str, str]]:
    """Parse authentication log entries from CSV content.

    The CSV **must** contain a header row with (at minimum) the columns:
    ``timestamp``, ``event_type``, ``username``, ``source_ip``.

    Parameters
    ----------
    content : str
        Raw CSV text (including the header row).

    Returns
    -------
    list[dict[str, str]]
        Same structure as :func:`parse_txt_log`.
    """
    events: list[dict[str, str]] = []
    reader = csv.DictReader(io.StringIO(content))

    for row in reader:
        # csv.DictReader lowercases nothing — we use the header as-is.
        timestamp = (row.get("timestamp") or "").strip()
        event_type = (row.get("event_type") or "").strip()
        username = (row.get("username") or "").strip()
        source_ip = (row.get("source_ip") or "").strip()

        if not timestamp or not event_type or not username:
            continue  # skip incomplete rows

        # Reconstruct a raw_log representation from the CSV fields
        raw_parts = [timestamp, event_type, username]
        if source_ip:
            raw_parts.append(source_ip)
        raw_log = ",".join(
            [timestamp, event_type, username, source_ip]
        )

        events.append(
            {
                "timestamp": timestamp,
                "event_type": event_type,
                "username": username,
                "source_ip": source_ip,
                "raw_log": raw_log,
            }
        )

    return events


# ═══════════════════════════════════════════════════════════════════════════
# 4. Event Normalisation
# ═══════════════════════════════════════════════════════════════════════════
def normalize_event(event: dict[str, str]) -> dict[str, str]:
    """Normalise a single parsed event dictionary **in-place** and return it.

    Normalisation rules:
    - Strip leading/trailing whitespace from all string values.
    - Upper-case ``event_type``.
    - Validate ``timestamp`` against ``YYYY-MM-DD HH:MM:SS``; set to empty
      string on failure.
    - Replace empty / whitespace-only ``source_ip`` with ``'N/A'``.

    Parameters
    ----------
    event : dict[str, str]
        A mutable event dictionary (modified in place).

    Returns
    -------
    dict[str, str]
        The same dict reference, now normalised.
    """
    # Strip whitespace from every value
    for key in event:
        if isinstance(event[key], str):
            event[key] = event[key].strip()

    # Upper-case event type
    event["event_type"] = event.get("event_type", "").upper()

    # Validate timestamp format
    ts = event.get("timestamp", "")
    try:
        datetime.strptime(ts, _TIMESTAMP_FMT)
    except (ValueError, TypeError):
        logger.warning("Invalid timestamp '%s' — clearing field.", ts)
        event["timestamp"] = ""

    # Default missing source_ip
    if not event.get("source_ip"):
        event["source_ip"] = "N/A"

    return event


# ═══════════════════════════════════════════════════════════════════════════
# 5. Orchestrator — parse_log_file
# ═══════════════════════════════════════════════════════════════════════════
def parse_log_file(
    filename: str,
    content: str,
) -> tuple[list[dict[str, str]], list[str]]:
    """Detect log format, parse, and normalise all events.

    The function determines the parser from the file extension, then
    iterates over the raw content line-by-line (for TXT) or row-by-row
    (for CSV), collecting per-line errors instead of aborting.

    Parameters
    ----------
    filename : str
        Original filename — used only for extension detection.
    content : str
        Full text content of the log file.

    Returns
    -------
    tuple[list[dict], list[str]]
        ``(events, errors)`` where *events* is the list of normalised
        dicts and *errors* lists human-readable error descriptions.
    """
    events: list[dict[str, str]] = []
    errors: list[str] = []

    if not content or not content.strip():
        errors.append("File is empty or contains only whitespace.")
        return events, errors

    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    # ── TXT parsing (line-by-line with error collection) ──────────────
    if ext == ".txt":
        for line_no, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            match = _TXT_LINE_RE.match(stripped)
            if not match:
                errors.append(
                    f"Line {line_no}: Malformed log entry — '{stripped}'"
                )
                continue

            event = {
                "timestamp": match.group(1).strip(),
                "event_type": match.group(2).strip(),
                "username": match.group(3).strip(),
                "source_ip": match.group(4).strip() if match.group(4) else "",
                "raw_log": stripped,
            }

            try:
                event = normalize_event(event)
                if not event["timestamp"]:
                    errors.append(
                        f"Line {line_no}: Invalid timestamp — '{stripped}'"
                    )
                    continue
                events.append(event)
            except Exception as exc:  # noqa: BLE001
                errors.append(
                    f"Line {line_no}: Normalisation error — {exc}"
                )

    # ── CSV parsing (row-by-row with error collection) ────────────────
    elif ext == ".csv":
        reader = csv.DictReader(io.StringIO(content))

        # Validate header
        expected_cols = {"timestamp", "event_type", "username", "source_ip"}
        if reader.fieldnames is None:
            errors.append("CSV file has no header row.")
            return events, errors

        actual_cols = {c.strip().lower() for c in reader.fieldnames}
        missing = expected_cols - actual_cols
        if missing:
            errors.append(
                f"CSV missing required columns: {', '.join(sorted(missing))}"
            )
            return events, errors

        for row_no, row in enumerate(reader, start=2):  # row 1 = header
            try:
                timestamp = (row.get("timestamp") or "").strip()
                event_type = (row.get("event_type") or "").strip()
                username = (row.get("username") or "").strip()
                source_ip = (row.get("source_ip") or "").strip()

                if not timestamp or not event_type or not username:
                    errors.append(
                        f"Row {row_no}: Missing required field(s)."
                    )
                    continue

                raw_log = ",".join(
                    [timestamp, event_type, username, source_ip]
                )

                event = {
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "username": username,
                    "source_ip": source_ip,
                    "raw_log": raw_log,
                }

                event = normalize_event(event)
                if not event["timestamp"]:
                    errors.append(
                        f"Row {row_no}: Invalid timestamp — '{timestamp}'"
                    )
                    continue

                events.append(event)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"Row {row_no}: Parse error — {exc}")

    else:
        errors.append(f"Unsupported file extension '{ext}'.")

    logger.info(
        "Parsed '%s': %d events, %d errors.", filename, len(events), len(errors)
    )
    return events, errors


# ═══════════════════════════════════════════════════════════════════════════
# 6. Database Storage
# ═══════════════════════════════════════════════════════════════════════════
def store_parsed_logs(
    events: list[dict[str, str]],
    uploaded_by: str,
    log_source: str = "AUTH",
) -> int:
    """Bulk-insert parsed events into the ``uploaded_logs`` table.

    Duplicate detection is performed on the composite of
    ``(timestamp, event_type, username, source_ip, raw_log)`` —
    existing rows that match are silently skipped.

    Parameters
    ----------
    events : list[dict[str, str]]
        Normalised event dicts (output of :func:`parse_log_file`).
    uploaded_by : str
        Username of the analyst uploading the logs.
    log_source : str, optional
        Value for the ``log_source`` column (default ``"AUTH"``).

    Returns
    -------
    int
        Number of newly inserted rows.
    """
    if not events:
        return 0

    conn = _get_conn()
    inserted = 0

    try:
        cursor = conn.cursor()

        for event in events:
            # ── Duplicate check ───────────────────────────────────────
            cursor.execute(
                """
                SELECT 1 FROM uploaded_logs
                WHERE timestamp  = ?
                  AND event_type = ?
                  AND username   = ?
                  AND source_ip  = ?
                  AND raw_log    = ?
                LIMIT 1
                """,
                (
                    event["timestamp"],
                    event["event_type"],
                    event["username"],
                    event["source_ip"],
                    event["raw_log"],
                ),
            )

            if cursor.fetchone() is not None:
                logger.debug(
                    "Skipping duplicate: %s %s %s",
                    event["timestamp"],
                    event["event_type"],
                    event["username"],
                )
                continue

            # ── Insert ────────────────────────────────────────────────
            cursor.execute(
                """
                INSERT INTO uploaded_logs
                    (timestamp, event_type, username, source_ip,
                     raw_log, log_source, uploaded_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["timestamp"],
                    event["event_type"],
                    event["username"],
                    event["source_ip"],
                    event["raw_log"],
                    log_source,
                    uploaded_by,
                ),
            )
            inserted += 1

        conn.commit()
        logger.info(
            "Stored %d/%d events (uploaded_by=%s).",
            inserted,
            len(events),
            uploaded_by,
        )
    except sqlite3.Error:
        conn.rollback()
        logger.exception("Database error while storing parsed logs.")
        raise
    finally:
        conn.close()

    return inserted


# ═══════════════════════════════════════════════════════════════════════════
# 7. Log Retrieval
# ═══════════════════════════════════════════════════════════════════════════
def get_uploaded_logs(limit: int = 500) -> list[dict[str, Any]]:
    """Retrieve uploaded log events ordered by timestamp descending.

    Parameters
    ----------
    limit : int, optional
        Maximum number of rows to return (default 500).

    Returns
    -------
    list[dict]
        Each dict mirrors the ``uploaded_logs`` table columns.
    """
    conn = _get_conn()

    try:
        cursor = conn.execute(
            """
            SELECT id, timestamp, event_type, username, source_ip,
                   raw_log, log_source, uploaded_by, uploaded_at
            FROM uploaded_logs
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════
# CLI smoke-test
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Quick self-test with a tiny inline log snippet
    sample_txt = (
        "2026-06-09 08:15:00 LOGIN_SUCCESS jsmith 192.168.1.10\n"
        "2026-06-09 08:16:00 LOGIN_SUCCESS agarcia\n"
        "THIS LINE IS MALFORMED\n"
        "2026-06-09 08:17:00 LOGOUT jsmith 192.168.1.10\n"
    )

    print("── TXT parse test ─────────────────────────────────")
    parsed_events, parse_errors = parse_log_file("test.txt", sample_txt)
    for ev in parsed_events:
        print(f"  {ev}")
    for err in parse_errors:
        print(f"  [ERR] {err}")

    sample_csv = (
        "timestamp,event_type,username,source_ip\n"
        "2026-06-09 09:00:00,LOGIN_SUCCESS,admin,10.0.0.1\n"
        "2026-06-09 09:05:00,LOGOUT,admin,\n"
    )

    print("\n── CSV parse test ─────────────────────────────────")
    parsed_events, parse_errors = parse_log_file("test.csv", sample_csv)
    for ev in parsed_events:
        print(f"  {ev}")
    for err in parse_errors:
        print(f"  [ERR] {err}")

    print("\n── Validation test ────────────────────────────────")
    print(validate_file("logs.txt", 1024))
    print(validate_file("logs.exe", 1024))
    print(validate_file("logs.csv", 20_000_000))
    print(validate_file("logs.txt", 0))
