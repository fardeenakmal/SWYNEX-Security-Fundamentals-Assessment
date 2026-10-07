# Finding SEC-VULN-002: Insecure Direct Object References (IDOR)

## Summary

| Metric | Value |
| :--- | :--- |
| **Finding ID** | SEC-VULN-002 |
| **Vulnerability Class** | Insecure Direct Object Reference (Broken Access Control) |
| **CWE ID** | [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) |
| **OWASP Category** | A01:2021 – Broken Access Control |
| **CVSS v3.1 Base Score** | **7.5 (High)** |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Affected Component** | `lab/vulnerable_app/server.py` (`handle_profile`), `lab/vulnerable_app/database.py` (`get_user_by_id_vulnerable`) |
| **Status** | **Remediated** |

---

## 1. Affected Component
- **Files:** `lab/vulnerable_app/server.py`, `lab/vulnerable_app/database.py`
- **Endpoint:** `GET /profile?id=<user_id>`
- **Function:** `handle_profile(user, params)`

---

## 2. Risk & Impact Analysis
- **Description:** The application takes an integer `id` from the URL query string and renders the corresponding user profile without checking if the currently authenticated user owns that profile or has administrative privileges.
- **Threat Scenario:**
  A logged-in customer (e.g. user `alice`, ID 2) changes the query parameter to `?id=1` or `?id=3`. The server directly delivers confidential data belonging to the other account, including full name, account number, email, and account balance.
- **CIA Impact:** Confidentiality (High), Integrity (None), Availability (None).

---

## 3. Technical Evidence & Vulnerable Code
```python
requested_id = params.get("id", [None])[0]
# FLAW: No verification that requested_id == user["id"] or user["role"] == "admin"
profile_data = database.get_user_by_id_vulnerable(int(requested_id))
```

---

## 4. Recommended Mitigation
1. **Server-Side Session Validation:** Validate that `requested_id == session["user"]["id"]`.
2. **Role-Based Authorization:** Allow foreign record access only if `session["user"]["role"] == "admin"`.
3. **Remediated Code:**
```python
if target_id != user["id"] and user["role"] != "admin":
    self.send_sanitized_error(403, "Access Denied: Unauthorized.")
    return
```
