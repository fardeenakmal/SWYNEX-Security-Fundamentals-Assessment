# Finding SEC-VULN-003: Cryptographic Failure (Weak MD5 Password Hashing)

## Summary

| Metric | Value |
| :--- | :--- |
| **Finding ID** | SEC-VULN-003 |
| **Vulnerability Class** | Cryptographic Failure / Insecure Storage |
| **CWE ID** | [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html) |
| **OWASP Category** | A02:2021 – Cryptographic Failures |
| **CVSS v3.1 Base Score** | **7.4 (High)** |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Affected Component** | `lab/vulnerable_app/database.py` (`weak_hash`, `init_db`) |
| **Status** | **Remediated** |

---

## 1. Affected Component
- **Files:** `lab/vulnerable_app/database.py`
- **Subsystem:** Password hashing and credential storage routines

---

## 2. Risk & Impact Analysis
- **Description:** User passwords are stored using unsalted MD5 digests.
- **Threat Scenario:**
  MD5 is computationally obsolete and lacks a key derivation factor. Hashes can be inverted in milliseconds using online rainbow table lookups or GPU-accelerated hash cracking. An attacker who gains read access to the database can instantly recover user passwords.
- **CIA Impact:** Confidentiality (High), Integrity (Low), Availability (None).

---

## 3. Technical Evidence & Vulnerable Code
```python
def weak_hash(password: str) -> str:
    # FLAW: MD5 is broken and unsalted
    return hashlib.md5(password.encode("utf-8")).hexdigest()
```

---

## 4. Recommended Mitigation
1. **PBKDF2-HMAC-SHA256:** Transition to PBKDF2 with at least 600,000 iterations (OWASP standard).
2. **Cryptographic Salt:** Generate a unique 16-byte random salt per password (`secrets.token_bytes(16)`).
3. **Constant-Time Verification:** Compare hashes using `secrets.compare_digest`.
4. **Remediated Code:** See `lab/secure_app/security_utils.py` (`hash_password`, `verify_password`).
