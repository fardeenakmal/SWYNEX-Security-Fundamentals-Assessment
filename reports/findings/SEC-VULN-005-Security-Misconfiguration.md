# Finding SEC-VULN-005: Security Misconfiguration (Error Disclosure & Missing Headers)

## Summary

| Metric | Value |
| :--- | :--- |
| **Finding ID** | SEC-VULN-005 |
| **Vulnerability Class** | Security Misconfiguration / Information Disclosure |
| **CWE ID** | [CWE-209: Error Message Information Leak](https://cwe.mitre.org/data/definitions/209.html) / [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) |
| **OWASP Category** | A05:2021 – Security Misconfiguration |
| **CVSS v3.1 Base Score** | **5.3 (Medium)** |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| **Affected Component** | `lab/vulnerable_app/server.py` (Global exception handling & HTTP response pipeline) |
| **Status** | **Remediated** |

---

## 1. Affected Component
- **Files:** `lab/vulnerable_app/server.py`
- **Subsystem:** HTTP header dispatch and exception handling

---

## 2. Risk & Impact Analysis
- **Description:** Unhandled exceptions dump detailed Python stack traces, local variables, and filesystem paths directly into the client browser. Furthermore, HTTP responses omit basic defensive headers like CSP, X-Frame-Options, and X-Content-Type-Options.
- **Threat Scenario:**
  Attackers induce errors (e.g. invalid types or malformed payloads) to map out server-side paths, framework versions, and database schemas. The absence of `X-Frame-Options` and `CSP` also leaves clients vulnerable to clickjacking.
- **CIA Impact:** Confidentiality (Low), Integrity (Low), Availability (None).

---

## 3. Technical Evidence & Vulnerable Code
```python
except Exception as e:
    self.send_response(500)
    # Traceback rendered directly into HTML response
    self.wfile.write(f"<pre>{traceback.format_exc()}</pre>".encode("utf-8"))
```

---

## 4. Recommended Mitigation
1. **Sanitized Error Pages:** Intercept exceptions and return standardized generic messages without stack traces.
2. **Defensive Headers:** Inject `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Strict-Transport-Security`.
3. **Remediated Code:** Implemented in `lab/secure_app/server.py` via `send_sanitized_error` and `apply_security_headers`.
