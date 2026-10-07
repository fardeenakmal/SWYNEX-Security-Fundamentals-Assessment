"""
SWYNEX Security Fundamentals Assessment - Authorized Vulnerable Lab Environment
Component: Vulnerable Database Access Layer (lab/vulnerable_app/database.py)

NOTICE: For authorized educational lab training only.
This module contains intentionally vulnerable patterns for security demonstration:
- CWE-89: Dynamic SQL string concatenation (SQL Injection)
- CWE-328 / CWE-312: Weak unsalted MD5 password hashing
"""

import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab_vulnerable.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(force: bool = False):
    """Initializes the SQLite database with mock training data."""
    if os.path.exists(DB_PATH):
        if not force:
            return
        try:
            os.remove(DB_PATH)
        except OSError:
            pass

    conn = get_db_connection()
    cursor = conn.cursor()

    # Create users table with weak MD5 password hashes
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

    # Create audit/search records table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            details TEXT NOT NULL
        )
    """)

    # Vulnerability CWE-328: Using legacy, unsalted MD5 hashing
    def weak_hash(password: str) -> str:
        return hashlib.md5(password.encode("utf-8")).hexdigest()

    # Seed mock records
    mock_users = [
        ("admin", weak_hash("AdminMaster!2026"), "System Administrator", "admin@swynex-lab.local", "admin", 99999.00, "SWYN-ADMIN-001"),
        ("alice", weak_hash("alice_secret_pass"), "Alice Jenkins", "alice@swynex-lab.local", "user", 1250.50, "SWYN-ACC-1002"),
        ("bob", weak_hash("bob_password_123"), "Bob Smith", "bob@swynex-lab.local", "user", 420.00, "SWYN-ACC-1003"),
        ("charlie", weak_hash("qwerty2026"), "Charlie Vance", "charlie@swynex-lab.local", "user", 85.25, "SWYN-ACC-1004"),
    ]

    cursor.executemany("""
        INSERT INTO users (username, password, full_name, email, role, balance, account_number)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, mock_users)

    mock_logs = [
        ("SYSTEM_INIT", "Database initialized in authorized training mode"),
        ("USER_LOGIN", "User alice authenticated successfully"),
        ("FUNDS_TRANSFER", "User alice transferred 50.0 to bob"),
        ("PASSWORD_RESET", "Password reset link requested for charlie"),
    ]

    cursor.executemany("""
        INSERT INTO audit_logs (action, details)
        VALUES (?, ?)
    """, mock_logs)

    conn.commit()
    conn.close()


def authenticate_user_vulnerable(username: str, password: str):
    """
    VULNERABILITY: SQL Injection (CWE-89)
    Dynamic string formatting allows arbitrary SQL commands to be injected,
    bypassing authentication logic or dumping tables.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Weak unsalted MD5 hash
    weak_pwd_hash = hashlib.md5(password.encode("utf-8")).hexdigest()

    # VULNERABLE: Direct concatenation of user input into SQL query string
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{weak_pwd_hash}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        return dict(user) if user else None
    finally:
        conn.close()


def get_user_by_id_vulnerable(user_id: int):
    """
    Fetches user record directly by ID without any authorization checks.
    Used in IDOR vulnerability demonstration.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, username, full_name, email, role, balance, account_number FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        return dict(user) if user else None
    finally:
        conn.close()


def search_audit_logs_vulnerable(search_term: str):
    """
    VULNERABILITY: SQL Injection (CWE-89) in search feature
    Direct string concatenation inside LIKE clause.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # VULNERABLE: Concatenated user query
    query = f"SELECT id, timestamp, action, details FROM audit_logs WHERE action LIKE '%{search_term}%' OR details LIKE '%{search_term}%'"
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        return [dict(row) for row in results]
    finally:
        conn.close()


def transfer_funds_vulnerable(from_user_id: int, to_username: str, amount: float):
    """
    Executes funds transfer without CSRF validation or balance sanity checks.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_user_id))
        cursor.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, to_username))
        cursor.execute("INSERT INTO audit_logs (action, details) VALUES (?, ?)", 
                       ("TRANSFER", f"User ID {from_user_id} transferred ${amount:.2f} to {to_username}"))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Vulnerable training database initialized at: {DB_PATH}")
