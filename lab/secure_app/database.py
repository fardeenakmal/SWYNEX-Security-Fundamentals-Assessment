"""
SWYNEX Security Fundamentals Assessment - Secure Hardened Lab Environment
Component: Hardened Database Access Layer (lab/secure_app/database.py)

Implements defense-in-depth mitigations:
- Parameterized Queries (Prepared Statements) eliminating SQL Injection (CWE-89)
- Cryptographic Password Hashing (PBKDF2-HMAC-SHA256) replacing weak MD5 (CWE-328)
- Safe Transaction Isolation
"""

import sqlite3
import os
import sys

# Ensure local imports work cleanly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import security_utils

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab_secure.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(force: bool = False):
    """Initializes the SQLite database with secure PBKDF2 hashed credentials."""
    if os.path.exists(DB_PATH):
        if not force:
            return
        try:
            os.remove(DB_PATH)
        except OSError:
            pass

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            balance REAL NOT NULL DEFAULT 100.0,
            account_number TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            details TEXT NOT NULL
        )
    """)

    # Seed users with modern PBKDF2 password hashes (iterations=600,000)
    mock_users = [
        ("admin", security_utils.hash_password("AdminMaster!2026"), "System Administrator", "admin@swynex-lab.local", "admin", 99999.00, "SWYN-ADMIN-001"),
        ("alice", security_utils.hash_password("alice_secret_pass"), "Alice Jenkins", "alice@swynex-lab.local", "user", 1250.50, "SWYN-ACC-1002"),
        ("bob", security_utils.hash_password("bob_password_123"), "Bob Smith", "bob@swynex-lab.local", "user", 420.00, "SWYN-ACC-1003"),
        ("charlie", security_utils.hash_password("qwerty2026"), "Charlie Vance", "charlie@swynex-lab.local", "user", 85.25, "SWYN-ACC-1004"),
    ]

    cursor.executemany("""
        INSERT INTO users (username, password, full_name, email, role, balance, account_number)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, mock_users)

    mock_logs = [
        ("SYSTEM_INIT", "Database initialized in hardened production mode"),
        ("SECURITY_AUDIT", "Parameterized query constraints and PBKDF2 verified"),
    ]

    cursor.executemany("""
        INSERT INTO audit_logs (action, details)
        VALUES (?, ?)
    """, mock_logs)

    conn.commit()
    conn.close()


def authenticate_user_secure(username: str, password_attempt: str):
    """
    SECURE: Uses parameterized query to retrieve the user record by username,
    then verifies the PBKDF2 hash using constant-time comparison.
    Completely immune to SQL Injection (CWE-89).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Parameterized query with '?' placeholder
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()

        if not user_row:
            # Mitigation for timing attacks: compute dummy hash to equalize response times
            security_utils.verify_password("dummy", "pbkdf2:sha256:1000$00$00")
            return None

        stored_hash = user_row["password"]
        if security_utils.verify_password(password_attempt, stored_hash):
            user_dict = dict(user_row)
            # Never keep hash in the memory representation of user object
            del user_dict["password"]
            return user_dict

        return None
    finally:
        conn.close()


def get_user_by_id_secure(user_id: int):
    """
    SECURE: Parameterized query to retrieve public profile attributes.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id, username, full_name, email, role, balance, account_number FROM users WHERE id = ?",
            (user_id,)
        )
        user = cursor.fetchone()
        return dict(user) if user else None
    finally:
        conn.close()


def search_audit_logs_secure(search_term: str):
    """
    SECURE: Parameterized query using wildcards inside the parameter tuple,
    eliminating SQL Injection in search routines.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    pattern = f"%{search_term}%"
    try:
        cursor.execute(
            "SELECT id, timestamp, action, details FROM audit_logs WHERE action LIKE ? OR details LIKE ?",
            (pattern, pattern)
        )
        results = cursor.fetchall()
        return [dict(row) for row in results]
    finally:
        conn.close()


def transfer_funds_secure(from_user_id: int, to_username: str, amount: float):
    """
    SECURE: Atomic transaction with server-side balance validation.
    """
    if amount <= 0:
        raise ValueError("Transfer amount must be strictly positive.")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE")

        # Verify sender balance
        cursor.execute("SELECT balance FROM users WHERE id = ?", (from_user_id,))
        sender = cursor.fetchone()
        if not sender or sender["balance"] < amount:
            raise ValueError("Insufficient funds for this transfer.")

        # Verify recipient existence
        cursor.execute("SELECT id FROM users WHERE username = ?", (to_username,))
        recipient = cursor.fetchone()
        if not recipient:
            raise ValueError("Recipient account not found.")

        # Perform atomic transfer
        cursor.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_user_id))
        cursor.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, to_username))
        cursor.execute(
            "INSERT INTO audit_logs (action, details) VALUES (?, ?)",
            ("TRANSFER_SECURE", f"User {from_user_id} transferred ${amount:.2f} to {to_username}")
        )

        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Hardened training database initialized at: {DB_PATH}")
