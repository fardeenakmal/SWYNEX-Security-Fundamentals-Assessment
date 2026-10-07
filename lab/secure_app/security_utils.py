"""
SWYNEX Security Fundamentals Assessment - Secure Hardened Lab Environment
Component: Security Controls & Hardening Utilities (lab/secure_app/security_utils.py)

Implements defense-in-depth security mitigations:
- Password Hashing: PBKDF2-HMAC-SHA256 with 600,000 iterations & CSPRNG salt (NIST SP 800-63B compliant)
- Rate Limiting: IP & Account based sliding window token bucket to prevent brute-force attacks
- Anti-CSRF Token Generation & Constant-Time Validation
- Cryptographically Secure Session ID Generation
- Security Response Headers Middleware
"""

import hashlib
import os
import secrets
import time
from collections import defaultdict


# ==========================================
# 1. Cryptographic Password Hashing (PBKDF2)
# ==========================================
PBKDF2_ITERATIONS = 600_000  # OWASP recommended work factor for PBKDF2-HMAC-SHA256
SALT_SIZE_BYTES = 16


def hash_password(password: str) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with a unique cryptographic salt.
    Returns format: pbkdf2:sha256:iterations$salt_hex$hash_hex
    """
    salt = secrets.token_bytes(SALT_SIZE_BYTES)
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )
    return f"pbkdf2:sha256:{PBKDF2_ITERATIONS}${salt.hex()}${derived_key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a password against the stored PBKDF2 hash using constant-time comparison.
    """
    try:
        algorithm, iterations_str, salt_hex, key_hex = stored_hash.split("$")[0].split(":")[0], stored_hash.split("$")[0].split(":")[2], stored_hash.split("$")[1], stored_hash.split("$")[2]
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)

        actual_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations
        )
        return secrets.compare_digest(actual_key, expected_key)
    except Exception:
        return False


# ==========================================
# 2. Rate Limiting (Token Bucket / Sliding Window)
# ==========================================
class RateLimiter:
    """
    Sliding window rate limiter to throttle login attempts and prevent brute-force attacks.
    """
    def __init__(self, max_requests=5, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.attempts = defaultdict(list)

    def is_allowed(self, identifier: str) -> bool:
        """Checks if the request from the identifier is allowed under rate limits."""
        now = time.time()
        # Filter out timestamps outside the active sliding window
        self.attempts[identifier] = [
            ts for ts in self.attempts[identifier] if now - ts < self.window_seconds
        ]
        if len(self.attempts[identifier]) >= self.max_requests:
            return False
        self.attempts[identifier].append(now)
        return True

    def retry_after(self, identifier: str) -> int:
        """Returns seconds until the next attempt is permitted."""
        if not self.attempts[identifier]:
            return 0
        oldest = min(self.attempts[identifier])
        return max(1, int(self.window_seconds - (time.time() - oldest)))


# Global rate limiter: 5 attempts per 60 seconds per IP/account
LOGIN_RATE_LIMITER = RateLimiter(max_requests=5, window_seconds=60)


# ==========================================
# 3. Session & Anti-CSRF Token Management
# ==========================================
class SessionManager:
    """
    Secure in-memory session manager using CSPRNG tokens and anti-CSRF synchronizers.
    """
    def __init__(self, session_lifetime_seconds=3600):
        self.sessions = {}
        self.session_lifetime = session_lifetime_seconds

    def create_session(self, user_data: dict) -> str:
        """Generates a high-entropy 256-bit cryptographically secure session identifier."""
        session_id = secrets.token_hex(32)
        csrf_token = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            "user": user_data,
            "created_at": time.time(),
            "expires_at": time.time() + self.session_lifetime,
            "csrf_token": csrf_token
        }
        return session_id

    def get_session(self, session_id: str):
        """Validates and retrieves the active session."""
        if not session_id or session_id not in self.sessions:
            return None
        sess = self.sessions[session_id]
        if time.time() > sess["expires_at"]:
            del self.sessions[session_id]
            return None
        return sess

    def destroy_session(self, session_id: str):
        """Invalidates a session on logout."""
        if session_id in self.sessions:
            del self.sessions[session_id]

    def validate_csrf(self, session_id: str, submitted_token: str) -> bool:
        """Validates anti-CSRF token using constant-time string comparison."""
        sess = self.get_session(session_id)
        if not sess or not submitted_token:
            return False
        return secrets.compare_digest(sess["csrf_token"], submitted_token)


SESSION_MANAGER = SessionManager()


# ==========================================
# 4. Defensive Security Headers
# ==========================================
SECURE_HEADERS = {
    # Content Security Policy (Prevents unauthorized script execution / XSS)
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self';",
    # Prevent clickjacking
    "X-Frame-Options": "DENY",
    # Prevent MIME type sniffing
    "X-Content-Type-Options": "nosniff",
    # Control referrer information leakage
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # Restrict dangerous browser features
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    # Ensure client enforces HTTPS in production environments
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    # Remove granular technology fingerprinting
    "Server": "Swynex-SecureGateway"
}
