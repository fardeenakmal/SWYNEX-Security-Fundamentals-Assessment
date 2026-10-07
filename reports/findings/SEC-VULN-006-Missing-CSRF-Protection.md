# Finding SEC-VULN-006: Insecure Design (Missing CSRF Defenses)

## Summary

| Metric | Value |
| :--- | :--- |
| **Finding ID** | SEC-VULN-006 |
| **Vulnerability Class** | Cross-Site Request Forgery (CSRF) |
| **CWE ID** | [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html) |
| **OWASP Category** | A04:2021 – Insecure Design |
| **CVSS v3.1 Base Score** | **6.5 (Medium)** |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` |
| **Affected Component** | `lab/vulnerable_app/server.py` (`handle_transfer_page`, `process_transfer`) |
| **Status** | **Remediated** |

---

## 1. Affected Component
- **Files:** `lab/vulnerable_app/server.py`
- **Endpoint:** `POST /transfer`
- **Function:** `process_transfer(user, post_params)`

---

## 2. Risk & Impact Analysis
- **Description:** The funds transfer action relies solely on standard session cookies without validating an anti-CSRF token or setting `SameSite=Strict`.
- **Threat Scenario:**
  A logged-in victim visits an attacker-controlled website. A hidden form or script issues an unauthorized `POST` request to `http://127.0.0.1:8080/transfer`. Because the browser automatically includes ambient cookies, the transfer executes under the victim's account without their explicit consent.
- **CIA Impact:** Confidentiality (None), Integrity (High), Availability (None).

---

## 3. Technical Evidence & Vulnerable Code
```python
def process_transfer(self, user, post_params):
    # FLAW: Executes financial transfer without CSRF token verification
    recipient = post_params.get("recipient", [""])[0]
    amount = float(post_params.get("amount", ["0"])[0])
    database.transfer_funds_vulnerable(user["id"], recipient, amount)
```

---

## 4. Recommended Mitigation
1. **Synchronizer Token Pattern:** Include a unique, unguessable cryptographic token in every state-changing form:
```html
<input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
```
2. **Server-Side Token Verification:** Reject requests where the submitted token does not match the session token via constant-time comparison (`secrets.compare_digest`).
3. **Cookie Hardening:** Mark cookies with `SameSite=Strict; HttpOnly; Secure`.
4. **Remediated Code:** Implemented in `lab/secure_app/security_utils.py` and `lab/secure_app/server.py`.
