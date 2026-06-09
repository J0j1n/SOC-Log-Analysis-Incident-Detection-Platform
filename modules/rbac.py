"""
SOC Platform — Role-Based Access Control (RBAC) Module
=======================================================
Centralises permission definitions and enforcement for the three platform
roles: **ADMIN**, **SOC_MANAGER**, and **SOC_ANALYST**.

Design
------
- A single ``PERMISSIONS`` dict is the *source of truth* — every access
  check and navigation menu is derived from it.
- ``require_permission`` is a *guard* function intended for Streamlit pages:
  it calls ``st.error`` / ``st.stop`` and records an ``UNAUTHORIZED_ACCESS``
  audit entry on denial.
- ``get_accessible_pages`` translates permission sets into human-readable
  page names for building dynamic sidebar navigation.

Functions
---------
- check_permission     : Pure boolean permission check (no side effects).
- require_permission   : Guard that halts the Streamlit page on denial.
- get_user_permissions : List every action a role is allowed to perform.
- get_accessible_pages : Derive the sidebar page list for a given role.

Usage::

    from modules.rbac import require_permission, get_accessible_pages
    require_permission(role="SOC_ANALYST", action="upload_logs")
    pages = get_accessible_pages("SOC_ANALYST")
"""

from __future__ import annotations

from typing import Optional

# ---------------------------------------------------------------------------
# Permission definitions — single source of truth
# ---------------------------------------------------------------------------

PERMISSIONS: dict[str, list[str]] = {
    "ADMIN": [
        "create_users",
        "delete_users",
        "manage_roles",
        "view_all_incidents",
        "close_incidents",
        "review_investigations",
        "view_audit_logs",
        "view_reports",
        "upload_logs",
        "view_alerts",
        "investigate_alerts",
        "add_notes",
        "create_incidents",
    ],
    "SOC_MANAGER": [
        "view_alerts",
        "view_all_incidents",
        "close_incidents",
        "review_investigations",
        "view_reports",
        "upload_logs",
    ],
    "SOC_ANALYST": [
        "view_alerts",
        "investigate_alerts",
        "add_notes",
        "create_incidents",
        "upload_logs",
    ],
}

# Mapping from *permissions* (or permission groups) to human-readable page
# names shown in the sidebar navigation.  Each entry is a tuple of
# ``(page_name, required_permissions)`` where the user needs **at least one**
# of the listed permissions to see the page.
_PAGE_PERMISSION_MAP: list[tuple[str, list[str]]] = [
    ("Dashboard", []),  # visible to every authenticated user
    ("Upload Logs", ["upload_logs"]),
    ("Alerts", ["view_alerts"]),
    ("Investigations", ["investigate_alerts", "review_investigations"]),
    ("Incidents", ["view_all_incidents", "create_incidents"]),
    ("Reports", ["view_reports"]),
    ("User Management", ["create_users"]),
    ("Audit Logs", ["view_audit_logs"]),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_permission(role: str, action: str) -> bool:
    """Check whether *role* is allowed to perform *action*.

    Parameters
    ----------
    role : str
        One of ``ADMIN``, ``SOC_MANAGER``, ``SOC_ANALYST``.
    action : str
        The action identifier (e.g. ``"upload_logs"``).

    Returns
    -------
    bool
        ``True`` if the role's permission list contains the action,
        ``False`` otherwise (including when the role is unknown).
    """
    role_permissions = PERMISSIONS.get(role.strip().upper(), [])
    return action.strip().lower() in role_permissions


def require_permission(role: str, action: str) -> bool:
    """Enforce a permission check inside a Streamlit page.

    If the user's *role* does **not** include *action*, this function:

    1. Displays an error banner via ``streamlit.error()``.
    2. Logs an ``UNAUTHORIZED_ACCESS`` event via the audit module.
    3. Calls ``streamlit.stop()`` to halt further page rendering.

    Parameters
    ----------
    role : str
        The current user's role.
    action : str
        The action being attempted.

    Returns
    -------
    bool
        Always ``True`` when the function returns normally (permission
        granted).  On denial the function **does not return** — it calls
        ``st.stop()``.
    """
    if check_permission(role, action):
        return True

    # --- Permission denied path ---
    # Import Streamlit lazily so unit tests can import this module without
    # requiring Streamlit to be installed or a running event loop.
    try:
        import streamlit as st

        st.error(
            "⛔ Access Denied — You do not have permission to perform "
            f"this action: **{action}**."
        )
        st.stop()
    except ImportError:
        # Streamlit not available (e.g. CLI tooling or tests) — raise
        # a standard exception instead.
        pass

    # Log the unauthorised attempt (best-effort; failures here must not
    # propagate and block the deny path).
    try:
        from modules.audit import log_action, UNAUTHORIZED_ACCESS

        log_action(
            username=role,  # role is the best identifier we have here
            action=UNAUTHORIZED_ACCESS,
            details=f"Denied action '{action}' for role '{role}'.",
        )
    except Exception:  # noqa: BLE001 — intentionally broad
        pass

    # If st.stop() was not available (non-Streamlit context), raise to
    # prevent silent fall-through.
    raise PermissionError(
        f"Role '{role}' is not permitted to perform action '{action}'."
    )


def get_user_permissions(role: str) -> list[str]:
    """Return the full list of actions permitted for *role*.

    Parameters
    ----------
    role : str
        One of ``ADMIN``, ``SOC_MANAGER``, ``SOC_ANALYST``.

    Returns
    -------
    list[str]
        A copy of the role's permission list, or an empty list if the
        role is unknown.
    """
    return list(PERMISSIONS.get(role.strip().upper(), []))


def get_accessible_pages(role: str) -> list[str]:
    """Derive the sidebar navigation page list for *role*.

    The mapping is:

    +-----------------------+---------------------------------------------+
    | Page                  | Required permission(s) — need **≥ 1**       |
    +=======================+=============================================+
    | Dashboard             | *(all roles)*                               |
    | Upload Logs           | ``upload_logs``                             |
    | Alerts                | ``view_alerts``                             |
    | Investigations        | ``investigate_alerts`` or                   |
    |                       | ``review_investigations``                   |
    | Incidents             | ``view_all_incidents`` or                   |
    |                       | ``create_incidents``                        |
    | Reports               | ``view_reports``                            |
    | User Management       | ``create_users``                            |
    | Audit Logs            | ``view_audit_logs``                         |
    +-----------------------+---------------------------------------------+

    Parameters
    ----------
    role : str
        The user's platform role.

    Returns
    -------
    list[str]
        Ordered list of page names the user should see.
    """
    user_perms = set(get_user_permissions(role))
    pages: list[str] = []

    for page_name, required_perms in _PAGE_PERMISSION_MAP:
        # Pages with an empty required list are visible to everyone
        if not required_perms or user_perms.intersection(required_perms):
            pages.append(page_name)

    return pages
