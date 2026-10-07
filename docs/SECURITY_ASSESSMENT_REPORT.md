# SWYNEX Security Fundamentals Assessment - Comprehensive Technical Security Report

**Document Title:** Comprehensive Web Application Security Assessment Report  
**Project Name:** SWYNEX Security Fundamentals Assessment  
**Author / Security Assessor:** Fardeen Akmal  
**Target Environment:** SWYNEX Authorized Isolated Lab Testbed  
**Date of Assessment:** October 2026  
**Document Version:** 1.0 (Final)  

---

## 1. Executive Summary

During October 2026, a comprehensive security fundamentals assessment was conducted against the authorized SWYNEX training web application environment. The primary objective of this assessment was to evaluate the application against core cybersecurity hygiene principles, identify implementation and design vulnerabilities across the OWASP Top 10 categories, document the technical risks and evidence, and architect robust, production-grade defensive mitigations.

The assessment identified **6 key vulnerabilities** spanning Critical, High, and Medium severity tiers:
- **1 Critical-severity finding:** SQL Injection (SQLi) in Authentication and Search Subsystems.
- **2 High-severity findings:** Insecure Direct Object References (IDOR) and Cryptographic Failures (Unsalted MD5 Password Hashes).
- **3 Medium-severity findings:** Missing Rate Limiting on Authentication, Security Misconfiguration (Verbose Error Disclosure & Missing Security Headers), and Missing Cross-Site Request Forgery (CSRF) Defenses.

Following identification, full remediations were developed and validated in a hardened reference implementation (`lab/secure_app/`), reducing residual risk across all identified vectors to **Low / Negligible**.

---

## 2. Risk Rating Methodology

Vulnerabilities are evaluated using the **Common Vulnerability Scoring System (CVSS v3.1)** and categorized according to the **OWASP Top 10:2021** standard:

| Severity Level | CVSS v3.1 Base Score Range | Description |
| :--- | :--- | :--- |
| **Critical** | 9.0 – 10.0 | Exploitation results in complete system takeover, total database compromise, or unrestricted administrative bypass. |
| **High** | 7.0 – 8.9 | Significant exposure of sensitive customer data (PII), horizontal privilege escalation, or integrity violation. |
| **Medium** | 4.0 – 6.9 | Information disclosure, brute-force vulnerabilities, or state tampering requiring specific user conditions. |
| **Low** | 0.1 – 3.9 | Minor misconfigurations, verbose banners, or non-sensitive information leakage. |

---

## 3. Summary of Findings

| Finding ID | Vulnerability Title | OWASP Category | CWE ID | CVSS v3.1 Score | Severity | Remediation Status |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| **SEC-VULN-001** | SQL Injection in Authentication & Search | A03:2021 - Injection | CWE-89 | **9.8** | `CRITICAL` | **REMEDIATED** |
| **SEC-VULN-002** | Insecure Direct Object Reference (IDOR) | A01:2021 - Broken Access Control | CWE-639 | **7.5** | `HIGH` | **REMEDIATED** |
| **SEC-VULN-003** | Cryptographic Failure: Weak MD5 Hashing | A02:2021 - Cryptographic Failures | CWE-328 | **7.4** | `HIGH` | **REMEDIATED** |
| **SEC-VULN-004** | Authentication: Missing Rate Limiting | A07:2021 - Identification & Auth | CWE-307 | **5.3** | `MEDIUM` | **REMEDIATED** |
| **SEC-VULN-005** | Security Misconfiguration: Headers & Errors | A05:2021 - Security Misconfiguration | CWE-209 / CWE-693 | **5.3** | `MEDIUM` | **REMEDIATED** |
| **SEC-VULN-006** | Insecure Design: Missing CSRF Defenses | A04:2021 - Insecure Design | CWE-352 | **6.5** | `MEDIUM` | **REMEDIATED** |

---

## 4. In-Depth Vulnerability Analysis

---

### SEC-VULN-001: SQL Injection (SQLi) in Authentication and Search Routines

#### 1. Affected Component
- **Source Files:** `lab/vulnerable_app/database.py` (Functions: `authenticate_user_vulnerable`, `search_audit_logs_vulnerable`)
- **HTTP Endpoints:** `POST /login`, `GET /search`
- **Underlying Layer:** SQLite Database Access Layer

#### 2. Risk Description & Threat Modeling
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (**9.8 - Critical**)
- **CWE Identification:** [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- **OWASP Classification:** A03:2021 – Injection
- **Impact Analysis:**
  - **Confidentiality (High):** An attacker can extract the entire database contents, including credentials, sensitive PII, account numbers, and transaction logs.
  - **Integrity (High):** An attacker can alter records, manipulate account balances, or insert malicious entries.
  - **Availability (High):** Untrusted input could execute destructive commands (`DROP TABLE`, corrupting database integrity).
- **Threat Scenario:**
  Because user inputs are concatenated directly into SQL command strings without parameterization or escaping, an unauthenticated attacker can supply standard SQL metacharacters (e.g. `' OR '1'='1`) to manipulate query logic, bypassing authentication as an administrator or querying unauthorized datasets.

#### 3. Technical Evidence & Code Audit
Inspection of `lab/vulnerable_app/database.py` reveals direct string interpolation:

```python
# Vulnerable Code Excerpt: lab/vulnerable_app/database.py
def authenticate_user_vulnerable(username: str, password: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    weak_pwd_hash = hashlib.md5(password.encode("utf-8")).hexdigest()

    # CRITICAL FLAW: User input directly interpolated into SQL command
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{weak_pwd_hash}'"
    cursor.execute(query)
    ...
```

Similarly, in the search routine:
```python
# Vulnerable Code Excerpt: lab/vulnerable_app/database.py
def search_audit_logs_vulnerable(search_term: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    # CRITICAL FLAW: Unescaped parameter in LIKE statement
    query = f"SELECT id, timestamp, action, details FROM audit_logs WHERE action LIKE '%{search_term}%' OR details LIKE '%{search_term}%'"
    cursor.execute(query)
    ...
```

#### 4. Recommended Mitigation
1. **Parameterized Queries (Prepared Statements):** Completely separate SQL code from user-supplied data using parameterized queries (`?` placeholders in Python DB-API / SQLite).
2. **Principle of Least Privilege:** Configure database service accounts with only the minimal privileges required (e.g., restrict DDL operations).
3. **Input Validation:** Enforce strict type, length, and format validation on incoming input parameters.

**Remediated Implementation (`lab/secure_app/database.py`):**
```python
def authenticate_user_secure(username: str, password_attempt: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # SECURE: Database engine treats 'username' strictly as data parameter
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        if not user_row:
            return None
        # Constant-time PBKDF2 hash verification
        if security_utils.verify_password(password_attempt, user_row["password"]):
            user_dict = dict(user_row)
            del user_dict["password"]
            return user_dict
        return None
    finally:
        conn.close()
```

---

### SEC-VULN-002: Insecure Direct Object Reference (IDOR) in User Profiles

#### 1. Affected Component
- **Source Files:** `lab/vulnerable_app/server.py` (Method: `handle_profile`), `lab/vulnerable_app/database.py` (`get_user_by_id_vulnerable`)
- **HTTP Endpoint:** `GET /profile?id=<user_id>`
- **Underlying Layer:** Business Logic & Authorization Controller

#### 2. Risk Description & Threat Modeling
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (**7.5 - High**)
- **CWE Identification:** [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- **OWASP Classification:** A01:2021 – Broken Access Control
- **Impact Analysis:**
  - **Confidentiality (High):** Standard authenticated users can inspect other users' private financial records, balance, account numbers, and personal email addresses by iterating over sequential integer IDs.
  - **Integrity (Low/None):** Read-only data leakage in this endpoint.
  - **Availability (None).**
- **Threat Scenario:**
  A malicious user logged in as User `alice` (ID: 2) can alter the URL query string to `?id=1` or `?id=3`. The server reads the target user ID from the request and renders the target's confidential financial profile without verifying whether the requesting session has authorization to access that specific record.

#### 3. Technical Evidence & Code Audit
Inspection of `lab/vulnerable_app/server.py` reveals the absence of access control checks:

```python
# Vulnerable Code Excerpt: lab/vulnerable_app/server.py
def handle_profile(self, user, params):
    # FLAW: Reading arbitrary ID directly from untrusted client parameter
    requested_id = params.get("id", [None])[0]
    ...
    # Direct database query without verifying session ownership or RBAC
    profile_data = database.get_user_by_id_vulnerable(int(requested_id))
    ...
```

#### 4. Recommended Mitigation
1. **Server-Side Session Binding:** Verify that `session["user_id"] == requested_id` before returning private profile data.
2. **Role-Based Access Control (RBAC):** Permit access to foreign records only if the authenticated user has verified administrative privileges (`user["role"] == "admin"`).
3. **Indirect Object References / Non-Sequential Identifiers:** Replace sequential integer IDs with cryptographically random UUIDv4 identifiers to prevent enumeration.

**Remediated Implementation (`lab/secure_app/server.py`):**
```python
def handle_profile(self, user, params):
    if not user:
        self.send_response(302)
        self.send_header("Location", "/login?error=Authentication+required")
        self.end_headers()
        return

    requested_id_str = params.get("id", [None])[0]
    target_id = user["id"] if not requested_id_str else int(requested_id_str)

    # SECURE: Strict contextual authorization check
    if target_id != user["id"] and user["role"] != "admin":
        logger.warning(f"Unauthorized IDOR attempt blocked: User {user['username']} tried accessing ID {target_id}")
        self.send_sanitized_error(403, "Access Denied: You do not possess authorization to inspect foreign records.")
        return

    profile_data = database.get_user_by_id_secure(target_id)
    ...
```

---

### SEC-VULN-003: Cryptographic Failure - Weak MD5 Password Hashing & Insecure Storage

#### 1. Affected Component
- **Source Files:** `lab/vulnerable_app/database.py` (Functions: `init_db`, `authenticate_user_vulnerable`)
- **Underlying Layer:** Data Persistence & Credential Management

#### 2. Risk Description & Threat Modeling
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (**7.4 - High**)
- **CWE Identification:** [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html) / [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- **OWASP Classification:** A02:2021 – Cryptographic Failures
- **Impact Analysis:**
  - **Confidentiality (High):** Passwords hashed with unsalted MD5 can be reversed in seconds using publicly accessible precomputed rainbow tables or high-speed GPU cracking.
  - **Integrity (Low):** Compromised credentials facilitate impersonation.
  - **Availability (None).**
- **Threat Scenario:**
  If an adversary obtains read access to the database (via backup leakage or SQL injection), the unsalted 32-character hexadecimal MD5 hashes can be trivially cracked, exposing plaintext credentials across the user base.

#### 3. Technical Evidence & Code Audit
Inspection of `lab/vulnerable_app/database.py`:

```python
# Vulnerable Code Excerpt: lab/vulnerable_app/database.py
def weak_hash(password: str) -> str:
    # CRITICAL FLAW: MD5 is broken, collision-prone, and unsalted
    return hashlib.md5(password.encode("utf-8")).hexdigest()
```

Example database record inspection:
```sql
SELECT username, password FROM users WHERE username = 'alice';
-- alice | c72b15... (32-character unsalted MD5 digest)
```

#### 4. Recommended Mitigation
1. **Adopt Modern Password Hashing Functions:** Migrate to **PBKDF2-HMAC-SHA256** (with at least 600,000 iterations according to OWASP guidelines), **Argon2id**, or **bcrypt**.
2. **Cryptographic Salting:** Generate a unique, cryptographically secure 16-byte random salt (`secrets.token_bytes(16)`) for every individual password.
3. **Constant-Time Comparison:** Use constant-time comparison (`secrets.compare_digest`) to prevent timing side-channel attacks during hash verification.

**Remediated Implementation (`lab/secure_app/security_utils.py`):**
```python
PBKDF2_ITERATIONS = 600_000

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2:sha256:{PBKDF2_ITERATIONS}${salt.hex()}${derived_key.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        _, iterations_str, salt_hex, key_hex = stored_hash.split("$")[0].split(":")[0], stored_hash.split("$")[0].split(":")[2], stored_hash.split("$")[1], stored_hash.split("$")[2]
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        actual_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations_str))
        return secrets.compare_digest(actual_key, expected_key)
    except Exception:
        return False
```

---

### SEC-VULN-004: Identification & Authentication Failures - Missing Rate Limiting

#### 1. Affected Component
- **Source Files:** `lab/vulnerable_app/server.py` (Method: `process_login`)
- **HTTP Endpoint:** `POST /login`
- **Underlying Layer:** Authentication Controller

#### 2. Risk Description & Threat Modeling
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` (**5.3 - Medium**)
- **CWE Identification:** [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- **OWASP Classification:** A07:2021 – Identification and Authentication Failures
- **Impact Analysis:**
  - **Confidentiality (Medium):** Enables brute-force attacks and credential stuffing against user accounts.
  - **Integrity (Medium):** Unauthorized account takeover.
  - **Availability (Low):** High request volume can strain backend resources.
- **Threat Scenario:**
  The login endpoint handles unlimited consecutive authentication attempts without delay, lockout, or CAPTCHA validation. An automated attacker can execute dictionary attacks against targeted usernames without being detected or restricted.

#### 3. Technical Evidence & Code Audit
Inspection of `lab/vulnerable_app/server.py`:
```python
# Vulnerable Code Excerpt: lab/vulnerable_app/server.py
def process_login(self, post_params):
    username = post_params.get("username", [""])[0]
    password = post_params.get("password", [""])[0]

    # FLAW: No attempt counter, IP rate limiting, or delay mechanism
    user = database.authenticate_user_vulnerable(username, password)
    ...
```

#### 4. Recommended Mitigation
1. **Sliding-Window Rate Limiting:** Track failed attempts per IP and per username, enforcing a limit (e.g. 5 attempts per 60 seconds).
2. **HTTP 429 Status Code:** Respond with `HTTP 429 Too Many Requests` and a standard `Retry-After` header when thresholds are exceeded.
3. **Progressive Delays & Account Lockout:** Introduce exponential backoff or temporary account locking after multiple successive failures.

**Remediated Implementation (`lab/secure_app/security_utils.py` & `server.py`):**
```python
# Sliding window rate limiter
LOGIN_RATE_LIMITER = RateLimiter(max_requests=5, window_seconds=60)

# Inside process_login:
limiter_key = f"{client_ip}:{username}"
if not security_utils.LOGIN_RATE_LIMITER.is_allowed(limiter_key):
    retry_seconds = security_utils.LOGIN_RATE_LIMITER.retry_after(limiter_key)
    self.send_response(429)
    self.send_header("Retry-After", str(retry_seconds))
    self.end_headers()
    return
```

---

### SEC-VULN-005: Security Misconfiguration - Verbose Error Messages & Missing HTTP Headers

#### 1. Affected Component
- **Source Files:** `lab/vulnerable_app/server.py` (Methods: `do_GET`, `do_POST`, `handle_index`)
- **HTTP Endpoints:** Global Application Responses
- **Underlying Layer:** HTTP Middleware & Error Handling Pipeline

#### 2. Risk Description & Threat Modeling
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` (**5.3 - Medium**)
- **CWE Identification:** [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) / [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- **OWASP Classification:** A05:2021 – Security Misconfiguration
- **Impact Analysis:**
  - **Confidentiality (Medium):** Raw stack traces reveal internal filesystem paths (`/home/user/...`), framework versioning, SQL schema syntax, and variable states.
  - **Integrity (Low):** Missing `Content-Security-Policy` and `X-Frame-Options` leaves the application vulnerable to framing, clickjacking, and XSS injection vectors.
- **Threat Scenario:**
  When an exception occurs, the vulnerable server sends the complete Python traceback and internal file paths directly to the client browser. Furthermore, the absence of defensive HTTP headers leaves client browsers susceptible to MIME-type sniffing and framing attacks.

#### 3. Technical Evidence & Code Audit
Inspection of `lab/vulnerable_app/server.py`:
```python
# Vulnerable Code Excerpt: lab/vulnerable_app/server.py
except Exception as e:
    # FLAW: Direct transmission of traceback to user browser
    self.send_response(500)
    self.send_header("Content-Type", "text/html; charset=utf-8")
    self.end_headers()
    err_html = f"<pre>{traceback.format_exc()}</pre>"
    self.wfile.write(err_html.encode("utf-8"))
```

Server response headers audit:
```http
HTTP/1.0 200 OK
Server: Swynex-Lab-Core/1.0.0-DEBUG   <-- Verbose fingerprinting
Content-Type: text/html; charset=utf-8
<-- Missing Content-Security-Policy
<-- Missing X-Frame-Options
<-- Missing X-Content-Type-Options
<-- Missing Referrer-Policy
```

#### 4. Recommended Mitigation
1. **Generic User-Facing Error Pages:** Return sanitized, friendly error messages without stack traces (`HTTP 500: An unexpected internal error occurred`).
2. **Internal Secure Logging:** Log detailed stack traces and debugging context exclusively to secure server-side log files.
3. **Mandatory Security Headers Middleware:** Enforce strict browser defense headers across all HTTP responses.

**Remediated Implementation (`lab/secure_app/security_utils.py`):**
```python
SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Server": "Swynex-Gateway"
}
```

---

### SEC-VULN-006: Insecure Design - Missing Cross-Site Request Forgery (CSRF) Defenses

#### 1. Affected Component
- **Source Files:** `lab/vulnerable_app/server.py` (Methods: `handle_transfer_page`, `process_transfer`)
- **HTTP Endpoint:** `POST /transfer`
- **Underlying Layer:** Session & State Management Layer

#### 2. Risk Description & Threat Modeling
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` (**6.5 - Medium**)
- **CWE Identification:** [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
- **OWASP Classification:** A04:2021 – Insecure Design
- **Impact Analysis:**
  - **Integrity (High):** An attacker can induce a victim's browser to execute unwanted financial transactions without the victim's knowledge.
  - **Confidentiality (None).**
  - **Availability (None).**
- **Threat Scenario:**
  The funds transfer endpoint relies exclusively on ambient session cookies without validating a unique anti-CSRF token. If an authenticated user visits an untrusted website while logged in, a hidden auto-submitting HTML form on that site can issue a transfer request that the user's browser executes with valid session cookies.

#### 3. Technical Evidence & Code Audit
Inspection of `lab/vulnerable_app/server.py`:
```python
# Vulnerable Code Excerpt: lab/vulnerable_app/server.py
def process_transfer(self, user, post_params):
    # FLAW: No anti-CSRF token verification
    recipient = post_params.get("recipient", [""])[0]
    amount = float(post_params.get("amount", ["0"])[0])
    database.transfer_funds_vulnerable(user["id"], recipient, amount)
```

Furthermore, the session cookie is created without defensive flags:
```http
Set-Cookie: session_id=sess_2_alice; Path=/
# Missing: HttpOnly, SameSite=Strict, Secure
```

#### 4. Recommended Mitigation
1. **Synchronizer Token Pattern:** Issue a unique, cryptographically random anti-CSRF token for each active session (`secrets.token_urlsafe(32)`).
2. **Token Validation on State Changes:** Reject any state-changing `POST`, `PUT`, or `DELETE` request that lacks a matching token using constant-time comparison.
3. **Modern Cookie Attributes:** Set `SameSite=Strict`, `HttpOnly`, and `Secure` on all session cookies to restrict cross-site transmission.

**Remediated Implementation (`lab/secure_app/server.py`):**
```python
# Synchronizer token validation
if not security_utils.SESSION_MANAGER.validate_csrf(session_id, submitted_csrf):
    logger.warning(f"CSRF token failure for user {user['username']}")
    self.send_sanitized_error(403, "Forbidden: Anti-CSRF token missing or invalid.")
    return
```

---

## 5. Verification and Retesting Results

Following implementation of the recommended mitigations in `lab/secure_app/`, the entire testbed was evaluated using automated unit test suites (`tests/test_security_controls.py`) and the automated defensive audit tool (`tools/security_auditor.py`):

| Test Suite / Control | Verification Target | Result | Status |
| :--- | :--- | :---: | :---: |
| **SQLi Immunity Test** | SQL injection authentication bypass payloads | `None returned` | **PASSED** |
| **Search Parameterization** | Metacharacter wildcard injection in search | `Literal string matched` | **PASSED** |
| **PBKDF2 Hash Test** | Unique per-user salt + 600,000 iterations | `Verified` | **PASSED** |
| **Rate Limiter Test** | Excessive rapid requests throttled at 5/min | `Blocked (HTTP 429)` | **PASSED** |
| **CSRF Validation Test** | Missing and forged token rejection | `Rejected (HTTP 403)` | **PASSED** |
| **Security Headers Test** | CSP, X-Frame-Options, X-Content-Type-Options | `All Present` | **PASSED** |

**Automated Test Result:** 7 of 7 unit tests passed with 100% compliance.

---

## 6. Strategic Recommendations & Roadmap

1. **Phase 1 (Immediate - Days 1–7):**
   - Enforce parameterized database queries across all legacy modules.
   - Configure centralized security response headers (`CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`).
   - Suppress detailed error disclosures in production web server configurations.

2. **Phase 2 (Medium Term - Weeks 2–4):**
   - Migrate all stored credentials to PBKDF2-HMAC-SHA256 or Argon2id with unique salts.
   - Implement anti-CSRF token middleware on all state-changing endpoints.
   - Enforce contextual authorization checks (RBAC) at the service controller layer.

3. **Phase 3 (Long Term - Ongoing):**
   - Integrate Static Application Security Testing (SAST) and Dependency Vulnerability Scanners into the CI/CD pipeline.
   - Establish regular internal penetration testing cycles and security awareness training for software engineering teams.

---

**Report Prepared By:**  
Fardeen Akmal  
*SWYNEX Security Fundamentals Assessment*
