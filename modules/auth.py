"""
SOC Platform — Authentication Module
=====================================
Handles user authentication, password management, and user lifecycle
operations for the SOC log-analysis platform.

Security design
---------------
- **bcrypt** with default cost factor for password hashing.
- **Constant-time** comparison via ``bcrypt.checkpw`` to prevent timing
  side-channels.
- **Generic error messages** on login failure — no distinction between
  "user not found" and "wrong password" to prevent username enumeration.
- All database queries use **parameterized statements** to eliminate SQL
  injection.

Functions
---------
- hash_password             : Hash a plaintext password with bcrypt.
- verify_password           : Constant-time password verification.
- validate_password_strength: Enforce password-complexity policy.
- authenticate_user         : Verify credentials against the users table.
- create_user               : Register a new user with validation.
- delete_user               : Soft-delete a user (set is_active=0).
- get_all_users             : List all active user accounts.
- update_user_role          : Change a user's role.

Usage::

    from modules.auth import authenticate_user, create_user
    user = authenticate_user("admin", "Admin@123")
"""

from __future__ import annotations

import os
import re
import sqlite3
from typing import Optional

import bcrypt

# ---------------------------------------------------------------------------
# Database helper
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "database", "soc.db"
)

VALID_ROLES: set[str] = {"ADMIN", "SOC_MANAGER", "SOC_ANALYST"}


def _get_conn() -> sqlite3.Connection:
    """Return a new SQLite connection with WAL mode & foreign keys enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Password utilities
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash *password* using bcrypt with the default work factor.

    Parameters
    ----------
    password : str
        Plaintext password to hash.

    Returns
    -------
    str
        The bcrypt hash as a UTF-8 string suitable for storage.
    """
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify *password* against a stored bcrypt *password_hash*.

    Uses ``bcrypt.checkpw`` which performs constant-time comparison
    internally, preventing timing-based side-channel attacks.

    Parameters
    ----------
    password : str
        Plaintext password to verify.
    password_hash : str
        Previously stored bcrypt hash.

    Returns
    -------
    bool
        ``True`` if the password matches, ``False`` otherwise.
    """
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except (ValueError, TypeError):
        # Malformed hash — treat as a non-match
        return False


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Enforce the platform password-complexity policy.

    Requirements
    ~~~~~~~~~~~~
    - Minimum 8 characters.
    - At least 1 uppercase letter (A-Z).
    - At least 1 digit (0-9).
    - At least 1 special character (``!@#$%^&*()_+-=[]{}|;':\",./<>?``).

    Parameters
    ----------
    password : str
        The candidate password to evaluate.

    Returns
    -------
    tuple[bool, str]
        ``(True, "")`` when the password meets all requirements, otherwise
        ``(False, "<human-readable error message>")``.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."

    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:'\",.<>/?\\`~]", password):
        return False, "Password must contain at least one special character."

    return True, ""


# ---------------------------------------------------------------------------
# User authentication
# ---------------------------------------------------------------------------


def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Authenticate a user against the ``users`` table.

    Only **active** accounts (``is_active = 1``) are eligible for login.

    Parameters
    ----------
    username : str
        The account username.
    password : str
        The plaintext password to verify.

    Returns
    -------
    dict | None
        A dict ``{"id": int, "username": str, "role": str}`` on success,
        or ``None`` if the credentials are invalid or the account is
        inactive.  The return value is deliberately generic to prevent
        username-enumeration attacks.
    """
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT id, username, password_hash, role FROM users "
            "WHERE username = ? AND is_active = 1",
            (username.strip(),),
        ).fetchone()

        if row is None:
            return None

        if not verify_password(password, row["password_hash"]):
            return None

        return {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------


def create_user(
    username: str, password: str, role: str, created_by: str
) -> tuple[bool, str]:
    """Register a new user account.

    Validates password strength, checks for duplicate usernames, hashes
    the password with bcrypt, and inserts the record.

    Parameters
    ----------
    username : str
        Desired username (must be unique).
    password : str
        Plaintext password (will be validated then hashed).
    role : str
        One of ``ADMIN``, ``SOC_MANAGER``, ``SOC_ANALYST``.
    created_by : str
        Username of the administrator creating this account.

    Returns
    -------
    tuple[bool, str]
        ``(True, "User created successfully.")`` on success, otherwise
        ``(False, "<error message>")``.
    """
    # --- Input validation ---
    clean_username = username.strip()
    if not clean_username:
        return False, "Username cannot be empty."

    role = role.strip().upper()
    if role not in VALID_ROLES:
        return False, f"Invalid role. Must be one of: {', '.join(sorted(VALID_ROLES))}."

    is_valid, msg = validate_password_strength(password)
    if not is_valid:
        return False, msg

    # --- Persist ---
    conn = _get_conn()
    try:
        # Check uniqueness (including inactive accounts to avoid confusion)
        existing = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (clean_username,)
        ).fetchone()
        if existing:
            return False, "Username already exists."

        hashed = hash_password(password)
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, created_by)
            VALUES (?, ?, ?, ?)
            """,
            (clean_username, hashed, role, created_by.strip()),
        )
        conn.commit()
        return True, "User created successfully."
    except sqlite3.IntegrityError:
        # Race-condition safety net — concurrent insert with same username
        return False, "Username already exists."
    finally:
        conn.close()


def delete_user(username: str) -> tuple[bool, str]:
    """Soft-delete a user by setting ``is_active = 0``.

    The record remains in the database for audit purposes; the user can no
    longer authenticate.

    Parameters
    ----------
    username : str
        Account to deactivate.

    Returns
    -------
    tuple[bool, str]
        ``(True, "User deleted successfully.")`` on success, otherwise
        ``(False, "<error message>")``.

    Notes
    -----
    Callers **must** ensure they are not deleting themselves — pass the
    acting user's name and compare before calling this function, or use
    the safety check built into this function which compares against the
    target username itself (i.e., ``delete_user`` will refuse if the
    target matches the current session user when called from the UI).
    Because this module is session-agnostic, the higher-level UI layer
    is responsible for the "cannot delete yourself" guard.  However, an
    additional ``current_user`` comparison is deliberately **not** added
    here to keep the function signature clean — the RBAC / UI layer
    enforces that policy.
    """
    clean_username = username.strip()
    if not clean_username:
        return False, "Username cannot be empty."

    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT id, is_active FROM users WHERE username = ?",
            (clean_username,),
        ).fetchone()

        if row is None:
            return False, "User not found."

        if row["is_active"] == 0:
            return False, "User is already deactivated."

        conn.execute(
            "UPDATE users SET is_active = 0 WHERE username = ?",
            (clean_username,),
        )
        conn.commit()
        return True, "User deleted successfully."
    finally:
        conn.close()


def get_all_users() -> list[dict]:
    """Return all **active** user accounts.

    Returns
    -------
    list[dict]
        Each dict contains ``id``, ``username``, ``role``, ``created_at``,
        ``created_by``.  Password hashes are **never** included.
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT id, username, role, created_at, created_by "
            "FROM users WHERE is_active = 1 ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def update_user_role(username: str, new_role: str) -> tuple[bool, str]:
    """Change an active user's role.

    Parameters
    ----------
    username : str
        Target account.
    new_role : str
        New role — must be one of ``ADMIN``, ``SOC_MANAGER``,
        ``SOC_ANALYST``.

    Returns
    -------
    tuple[bool, str]
        ``(True, "Role updated successfully.")`` on success, otherwise
        ``(False, "<error message>")``.
    """
    clean_username = username.strip()
    new_role = new_role.strip().upper()

    if new_role not in VALID_ROLES:
        return False, f"Invalid role. Must be one of: {', '.join(sorted(VALID_ROLES))}."

    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ? AND is_active = 1",
            (clean_username,),
        ).fetchone()

        if row is None:
            return False, "User not found or inactive."

        conn.execute(
            "UPDATE users SET role = ? WHERE username = ?",
            (new_role, clean_username),
        )
        conn.commit()
        return True, "Role updated successfully."
    finally:
        conn.close()
