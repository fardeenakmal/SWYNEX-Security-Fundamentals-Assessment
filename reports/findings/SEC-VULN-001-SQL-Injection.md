# Finding SEC-VULN-001: SQL Injection (SQLi) in Authentication and Search

## Summary

| Metric | Value |
| :--- | :--- |
| **Finding ID** | SEC-VULN-001 |
| **Vulnerability Class** | SQL Injection |
| **CWE ID** | [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) |
| **OWASP Category** | A03:2021 – Injection |
| **CVSS v3.1 Base Score** | **9.8 (Critical)** |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Affected Component** | `lab/vulnerable_app/database.py` (`authenticate_user_vulnerable`, `search_audit_logs_vulnerable`) |
| **Status** | **Remediated** |

---

## 1. Affected Component
- **Files:** `lab/vulnerable_app/database.py`, `lab/vulnerable_app/server.py`
- **Endpoints:** `POST /login`, `GET /search`
- **Functions:** `authenticate_user_vulnerable(username, password)`, `search_audit_logs_vulnerable(search_term)`

---

## 2. Risk & Impact Analysis
- **Description:** Unsanitized user inputs are directly concatenated into SQL query strings.
- **Threat Scenario:**
  An unauthenticated remote attacker can inject SQL syntax (e.g. `' OR '1'='1`) into the login form or search box. This permits:
  1. Complete authentication bypass without knowing passwords.
  2. Unauthorized data exfiltration (dumping credentials, account balances, and audit logs).
  3. Alteration or destruction of database records.
- **CIA Impact:** Confidentiality (High), Integrity (High), Availability (High).

---

## 3. Technical Evidence & Vulnerable Code
In `lab/vulnerable_app/database.py`, user parameters are directly formatted into the query string:
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{weak_pwd_hash}'"
cursor.execute(query)
```
In the search handler:
```python
query = f"SELECT id, timestamp, action, details FROM audit_logs WHERE action LIKE '%{search_term}%' OR details LIKE '%{search_term}%'"
cursor.execute(query)
```

---

## 4. Recommended Mitigation
1. **Parameterized Queries:** Use prepared statements with `?` placeholders so input is strictly treated as data.
2. **Defensive Coding:**
```python
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```
3. **Automated Verification:** Verified in `tests/test_security_controls.py` via `test_sql_injection_defense_in_authentication` and `test_sql_injection_in_search_returns_literal_match`.
