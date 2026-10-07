# Finding SEC-VULN-004: Missing Rate Limiting and Account Lockout

## Summary

| Metric | Value |
| :--- | :--- |
| **Finding ID** | SEC-VULN-004 |
| **Vulnerability Class** | Identification and Authentication Failure |
| **CWE ID** | [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) |
| **OWASP Category** | A07:2021 – Identification and Authentication Failures |
| **CVSS v3.1 Base Score** | **5.3 (Medium)** |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| **Affected Component** | `lab/vulnerable_app/server.py` (`process_login`) |
| **Status** | **Remediated** |

---

## 1. Affected Component
- **Files:** `lab/vulnerable_app/server.py`
- **Endpoint:** `POST /login`
- **Function:** `process_login(post_params)`

---

## 2. Risk & Impact Analysis
- **Description:** The authentication interface processes unlimited login requests without throttling, progressive delays, or lockout mechanisms.
- **Threat Scenario:**
  An adversary can execute automated dictionary attacks or credential stuffing against known usernames without encountering any rate restriction or detection.
- **CIA Impact:** Confidentiality (Low), Integrity (Low), Availability (None).

---

## 3. Technical Evidence & Vulnerable Code
In `lab/vulnerable_app/server.py`, the login handler directly invokes authentication without checking client attempt frequency:
```python
def process_login(self, post_params):
    username = post_params.get("username", [""])[0]
    password = post_params.get("password", [""])[0]
    # No request counter or delay
    user = database.authenticate_user_vulnerable(username, password)
```

---

## 4. Recommended Mitigation
1. **Sliding-Window Rate Limiter:** Enforce a maximum threshold of 5 attempts per 60 seconds per IP/account.
2. **HTTP 429 Status:** Return `429 Too Many Requests` with `Retry-After: <seconds>`.
3. **Remediated Implementation:** Implemented in `lab/secure_app/security_utils.py` via `RateLimiter` class and integrated into `lab/secure_app/server.py`.
