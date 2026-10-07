# SWYNEX Security Fundamentals Assessment - Developer Remediation Guide

This guide provides practical, actionable technical remediation patterns for software engineers and systems architects to resolve the security vulnerabilities identified during the SWYNEX assessment.

---

## 1. Remediation: SQL Injection (CWE-89)

### The Vulnerability
Dynamic concatenation of user input directly into SQL strings allows attackers to alter query logic or execute unauthorized queries.

### Vulnerable Pattern
```python
# VULNERABLE: Direct string formatting into SQL statement
def authenticate(username, password_hash):
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
    cursor.execute(query)
    return cursor.fetchone()
```

### Secure Remediated Pattern
Always use parameterized queries (prepared statements). The database engine compiles the query template first, treating user input strictly as literal data values.

```python
# SECURE: Parameterized prepared statement
def authenticate(username, password_hash):
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password_hash))
    return cursor.fetchone()
```

---

## 2. Remediation: Insecure Direct Object References (IDOR - CWE-639)

### The Vulnerability
Accepting an object identifier (such as `user_id=3`) directly from client request parameters without validating that the authenticated session owns that resource.

### Vulnerable Pattern
```python
# VULNERABLE: Direct database fetch from query parameter
def get_profile(request):
    user_id = request.params.get("id")
    # Missing session-to-resource ownership check!
    return database.query_user(user_id)
```

### Secure Remediated Pattern
Enforce contextual authorization. Verify that the requested ID matches the session identity or that the user has verified administrative roles.

```python
# SECURE: Contextual authorization validation
def get_profile(session, request):
    requested_id = int(request.params.get("id"))
    current_user = session.get("user")

    if not current_user:
        raise AuthenticationRequiredError()

    # Enforce access boundaries
    if requested_id != current_user["id"] and current_user["role"] != "admin":
        logger.warning(f"Forbidden access attempt by {current_user['username']} to record {requested_id}")
        raise PermissionDeniedError("You are not authorized to view this record.")

    return database.query_user(requested_id)
```

---

## 3. Remediation: Weak Password Hashing (CWE-328 / CWE-312)

### The Vulnerability
Using fast, unsalted, obsolete cryptographic hash functions like MD5 or SHA1.

### Vulnerable Pattern
```python
# VULNERABLE: Fast, unsalted MD5 hash
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```

### Secure Remediated Pattern
Use a modern, slow, memory-hard key derivation function (PBKDF2-HMAC-SHA256 with 600,000 iterations, Argon2id, or bcrypt) with a unique cryptographically secure random salt per user.

```python
# SECURE: PBKDF2-HMAC-SHA256 with random salt
import hashlib
import secrets

PBKDF2_ITERATIONS = 600_000

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )
    return f"pbkdf2:sha256:{PBKDF2_ITERATIONS}${salt.hex()}${derived_key.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        _, iterations_str, salt_hex, key_hex = stored_hash.split("$")[0].split(":")[0], stored_hash.split("$")[0].split(":")[2], stored_hash.split("$")[1], stored_hash.split("$")[2]
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        actual_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(iterations_str)
        )
        return secrets.compare_digest(actual_key, expected_key)
    except Exception:
        return False
```

---

## 4. Remediation: Missing Rate Limiting (CWE-307)

### The Vulnerability
Allowing unlimited automated requests against authentication interfaces, facilitating dictionary attacks and credential stuffing.

### Secure Remediated Pattern
Implement a sliding-window rate limiter per IP address and account identifier:

```python
import time
from collections import defaultdict

class SlidingWindowRateLimiter:
    def __init__(self, max_requests=5, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.history = defaultdict(list)

    def is_allowed(self, client_key: str) -> bool:
        now = time.time()
        self.history[client_key] = [
            ts for ts in self.history[client_key] if now - ts < self.window_seconds
        ]
        if len(self.history[client_key]) >= self.max_requests:
            return False
        self.history[client_key].append(now)
        return True
```

When throttled, return `HTTP 429 Too Many Requests` with a `Retry-After: <seconds>` header.

---

## 5. Remediation: Verbose Error Messages & Security Headers (CWE-209 / CWE-693)

### The Vulnerability
Exposing internal exception tracebacks, server versions, and omitting modern HTTP security headers.

### Secure Remediated Pattern
1. Configure centralized middleware to inject security headers into every HTTP response:
```python
SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Server": "Swynex-Gateway"
}
```

2. Intercept unhandled exceptions globally and return sanitized user messages:
```python
try:
    process_request()
except Exception as exc:
    # Log detailed traceback internally for engineering triage
    logger.error("Unhandled request failure", exc_info=True)
    # Return sanitized generic response to user
    return HttpResponse(status=500, body="An unexpected error occurred. Please try again later.")
```

---

## 6. Remediation: Cross-Site Request Forgery (CSRF - CWE-352)

### The Vulnerability
Executing state-changing actions (e.g. transfers, password updates) using ambient cookies without verifying a unique request token.

### Secure Remediated Pattern
1. Embed an anti-CSRF synchronizer token into HTML forms:
```html
<form method="POST" action="/transfer">
    <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
    <!-- Form fields -->
</form>
```

2. Verify the submitted token against the active session token in constant time:
```python
import secrets

def validate_csrf(session_token: str, submitted_token: str) -> bool:
    if not session_token or not submitted_token:
        return False
    return secrets.compare_digest(session_token, submitted_token)
```

3. Set `SameSite=Strict` and `HttpOnly` on all authentication session cookies:
```http
Set-Cookie: secure_session=...; Path=/; HttpOnly; SameSite=Strict; Secure
```
