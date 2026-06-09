"""
SOC Platform — Detection Engine
================================
Rule-based threat detection functions that analyse a pandas DataFrame of
normalised security log events and return alert dictionaries ready for
ingestion by the alerts module.

Each detection function returns ``list[dict]`` where every dict has the
keys expected by ``alerts.create_alert``.

MITRE ATT&CK mappings
---------------------
| Detection              | Tactic               | ID    | Technique                               |
|------------------------|-----------------------|-------|-----------------------------------------|
| Brute Force            | Credential Access     | T1110 | Brute Force                             |
| Suspicious Login Time  | Initial Access        | T1078 | Valid Accounts                          |
| Privilege Escalation   | Privilege Escalation  | T1068 | Exploitation for Privilege Escalation   |
| Excessive User Creation| Persistence           | T1136 | Create Account                          |

Usage::

    import pandas as pd
    from modules.detector import run_all_detections

    logs_df = pd.DataFrame(...)  # columns: timestamp, event_type, username, source_ip, raw_log
    alerts = run_all_detections(logs_df)
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BRUTE_FORCE_WINDOW = timedelta(minutes=5)
_BRUTE_FORCE_THRESHOLD = 5

_SUSPICIOUS_HOUR_START = 0   # midnight
_SUSPICIOUS_HOUR_END = 4     # up-to 04:59

_USER_CREATION_WINDOW = timedelta(minutes=10)
_USER_CREATION_THRESHOLD = 3  # alert when count > 3

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ensure_datetime(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of *df* with the ``timestamp`` column parsed to datetime.

    If the column is already datetime-typed it is returned untouched.
    Unparsable values are coerced to ``NaT`` and the corresponding rows
    are dropped so downstream windowing never encounters non-datetime data.
    """
    df = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    return df


def _build_alert(
    threat_type: str,
    severity: str,
    source_ip: str,
    affected_user: str,
    description: str,
    mitre_tactic: str,
    mitre_technique_id: str,
    mitre_technique_name: str,
) -> dict[str, Any]:
    """Construct a standardised alert dict."""
    return {
        "threat_type": threat_type,
        "severity": severity,
        "source_ip": source_ip,
        "affected_user": affected_user,
        "description": description,
        "mitre_tactic": mitre_tactic,
        "mitre_technique_id": mitre_technique_id,
        "mitre_technique_name": mitre_technique_name,
    }


# ---------------------------------------------------------------------------
# Detection 1 — Brute Force
# ---------------------------------------------------------------------------


def detect_brute_force(logs_df: pd.DataFrame) -> list[dict]:
    """Detect brute-force login attempts.

    Groups ``FAILED_LOGIN`` events by ``source_ip`` and applies a 5-minute
    sliding window.  If **≥ 5** failures occur inside any window the
    function emits a **HIGH** severity alert.

    Parameters
    ----------
    logs_df:
        DataFrame with columns ``timestamp``, ``event_type``, ``username``,
        ``source_ip``, ``raw_log``.

    Returns
    -------
    list[dict]
        Alert dictionaries (may be empty).
    """
    alerts: list[dict] = []

    if logs_df.empty:
        return alerts

    df = _ensure_datetime(logs_df)
    failed = df[df["event_type"] == "FAILED_LOGIN"].copy()

    if failed.empty:
        return alerts

    failed = failed.sort_values("timestamp")

    for source_ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp").reset_index(drop=True)
        timestamps = group["timestamp"].tolist()
        usernames = group["username"].tolist()

        # Sliding-window: for each row, look ahead within the window span
        window_start = 0
        n = len(timestamps)

        for window_end in range(n):
            # Advance the start pointer to maintain the window size
            while timestamps[window_end] - timestamps[window_start] > _BRUTE_FORCE_WINDOW:
                window_start += 1

            count_in_window = window_end - window_start + 1

            if count_in_window >= _BRUTE_FORCE_THRESHOLD:
                # Collect unique usernames targeted in this window
                affected = sorted(
                    set(usernames[window_start: window_end + 1])
                )
                affected_str = ", ".join(affected)

                description = (
                    f"Brute-force detected from {source_ip}: "
                    f"{count_in_window} failed login attempts within "
                    f"5 minutes targeting user(s): {affected_str}"
                )

                alert = _build_alert(
                    threat_type="Brute Force",
                    severity="HIGH",
                    source_ip=str(source_ip),
                    affected_user=affected_str,
                    description=description,
                    mitre_tactic="Credential Access",
                    mitre_technique_id="T1110",
                    mitre_technique_name="Brute Force",
                )
                alerts.append(alert)
                logger.info("Brute-force alert: %s → %s", source_ip, affected_str)

                # Skip ahead past this window to avoid duplicate alerts for
                # the same burst from the same IP.
                break

    return alerts


# ---------------------------------------------------------------------------
# Detection 2 — Suspicious Login Time
# ---------------------------------------------------------------------------


def detect_suspicious_login_time(logs_df: pd.DataFrame) -> list[dict]:
    """Flag successful logins that occur between midnight and 04:59 AM.

    Each qualifying event generates an independent **MEDIUM** severity
    alert.

    Parameters
    ----------
    logs_df:
        DataFrame with columns ``timestamp``, ``event_type``, ``username``,
        ``source_ip``, ``raw_log``.

    Returns
    -------
    list[dict]
        Alert dictionaries (may be empty).
    """
    alerts: list[dict] = []

    if logs_df.empty:
        return alerts

    df = _ensure_datetime(logs_df)
    logins = df[df["event_type"] == "LOGIN_SUCCESS"].copy()

    if logins.empty:
        return alerts

    suspicious = logins[
        logins["timestamp"].dt.hour.between(_SUSPICIOUS_HOUR_START, _SUSPICIOUS_HOUR_END)
    ]

    for _, row in suspicious.iterrows():
        ts = row["timestamp"]
        description = (
            f"Suspicious login at {ts.strftime('%Y-%m-%d %H:%M:%S')} "
            f"by user '{row['username']}' from {row['source_ip']}. "
            f"Login occurred outside normal business hours."
        )

        alert = _build_alert(
            threat_type="Suspicious Login Time",
            severity="MEDIUM",
            source_ip=str(row["source_ip"]),
            affected_user=str(row["username"]),
            description=description,
            mitre_tactic="Initial Access",
            mitre_technique_id="T1078",
            mitre_technique_name="Valid Accounts",
        )
        alerts.append(alert)
        logger.info(
            "Suspicious login-time alert: user=%s ip=%s at %s",
            row["username"],
            row["source_ip"],
            ts,
        )

    return alerts


# ---------------------------------------------------------------------------
# Detection 3 — Privilege Escalation
# ---------------------------------------------------------------------------


def detect_privilege_escalation(logs_df: pd.DataFrame) -> list[dict]:
    """Flag every ``PRIVILEGE_ESCALATION`` event as a **CRITICAL** alert.

    Parameters
    ----------
    logs_df:
        DataFrame with columns ``timestamp``, ``event_type``, ``username``,
        ``source_ip``, ``raw_log``.

    Returns
    -------
    list[dict]
        Alert dictionaries (may be empty).
    """
    alerts: list[dict] = []

    if logs_df.empty:
        return alerts

    df = _ensure_datetime(logs_df)
    priv_esc = df[df["event_type"] == "PRIVILEGE_ESCALATION"]

    for _, row in priv_esc.iterrows():
        ts = row["timestamp"]
        description = (
            f"Privilege escalation detected for user '{row['username']}' "
            f"from {row['source_ip']} at {ts.strftime('%Y-%m-%d %H:%M:%S')}. "
            f"Immediate investigation required."
        )

        alert = _build_alert(
            threat_type="Privilege Escalation",
            severity="CRITICAL",
            source_ip=str(row["source_ip"]),
            affected_user=str(row["username"]),
            description=description,
            mitre_tactic="Privilege Escalation",
            mitre_technique_id="T1068",
            mitre_technique_name="Exploitation for Privilege Escalation",
        )
        alerts.append(alert)
        logger.info(
            "Privilege escalation alert: user=%s ip=%s",
            row["username"],
            row["source_ip"],
        )

    return alerts


# ---------------------------------------------------------------------------
# Detection 4 — Excessive User Creation
# ---------------------------------------------------------------------------


def detect_excessive_user_creation(logs_df: pd.DataFrame) -> list[dict]:
    """Detect bursts of ``USER_CREATED`` events.

    Events are grouped into **10-minute** tumbling windows.  If any window
    contains **more than 3** events, a **HIGH** severity alert is generated.

    Parameters
    ----------
    logs_df:
        DataFrame with columns ``timestamp``, ``event_type``, ``username``,
        ``source_ip``, ``raw_log``.

    Returns
    -------
    list[dict]
        Alert dictionaries (may be empty).
    """
    alerts: list[dict] = []

    if logs_df.empty:
        return alerts

    df = _ensure_datetime(logs_df)
    user_created = df[df["event_type"] == "USER_CREATED"].copy()

    if user_created.empty:
        return alerts

    user_created = user_created.sort_values("timestamp")
    user_created = user_created.set_index("timestamp")

    # Resample into 10-minute windows
    for window_end, group in user_created.resample(f"{int(_USER_CREATION_WINDOW.total_seconds() // 60)}min"):
        if len(group) > _USER_CREATION_THRESHOLD:
            created_users = ", ".join(sorted(group["username"].unique()))
            source_ips = ", ".join(sorted(group["source_ip"].unique()))
            window_start = window_end - _USER_CREATION_WINDOW

            description = (
                f"Excessive user creation detected: {len(group)} accounts "
                f"created within a 10-minute window "
                f"({window_start.strftime('%H:%M')}–{window_end.strftime('%H:%M')}). "
                f"Users created: {created_users}. Source IP(s): {source_ips}."
            )

            alert = _build_alert(
                threat_type="Excessive User Creation",
                severity="HIGH",
                source_ip=source_ips,
                affected_user=created_users,
                description=description,
                mitre_tactic="Persistence",
                mitre_technique_id="T1136",
                mitre_technique_name="Create Account",
            )
            alerts.append(alert)
            logger.info(
                "Excessive user-creation alert: %d accounts in window ending %s",
                len(group),
                window_end,
            )

    return alerts


# ---------------------------------------------------------------------------
# Combined runner
# ---------------------------------------------------------------------------


def run_all_detections(logs_df: pd.DataFrame) -> list[dict]:
    """Execute **all** detection rules against *logs_df* and return the
    combined list of alert dicts.

    Parameters
    ----------
    logs_df:
        DataFrame with columns ``timestamp``, ``event_type``, ``username``,
        ``source_ip``, ``raw_log``.

    Returns
    -------
    list[dict]
        Merged results from every detection function.
    """
    if logs_df.empty:
        logger.info("Empty DataFrame received — skipping all detections.")
        return []

    all_alerts: list[dict] = []

    detectors = [
        ("Brute Force", detect_brute_force),
        ("Suspicious Login Time", detect_suspicious_login_time),
        ("Privilege Escalation", detect_privilege_escalation),
        ("Excessive User Creation", detect_excessive_user_creation),
    ]

    for name, func in detectors:
        try:
            results = func(logs_df)
            logger.info("Detection '%s' produced %d alert(s).", name, len(results))
            all_alerts.extend(results)
        except Exception:
            logger.exception("Detection '%s' failed — skipping.", name)

    logger.info("Total alerts generated: %d", len(all_alerts))
    return all_alerts
