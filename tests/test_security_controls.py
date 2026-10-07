"""
SWYNEX Security Fundamentals Assessment - Automated Security Verification Tests
Component: Automated Defense & Control Verification Suite (tests/test_security_controls.py)

Tests defensive remediations against OWASP Top 10 vulnerabilities:
- Parameterized SQL Query Immunity (CWE-89)
- Cryptographic Salted Hashing & Constant-Time Verification (CWE-328 / CWE-312)
- Rate Limiting Threshold Enforcement (CWE-307)
- CSRF Token Generation & Constant-Time Verification (CWE-352)
"""

import unittest
import os
import sys

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from lab.secure_app import security_utils, database


class TestSecurityControls(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Initialize clean test database."""
        database.init_db()

    def test_sql_injection_defense_in_authentication(self):
        """
        Verify that parameterized queries neutralize SQL injection authentication bypass payloads.
        """
        sqli_payloads = [
            "' OR '1'='1",
            "admin' --",
            "' UNION SELECT 1, 'admin', 'pass', 'Full', 'email', 'admin', 100, 'acc' --",
            "' OR 1=1 /*",
            "admin' /*"
        ]

        for payload in sqli_payloads:
            with self.subTest(payload=payload):
                result = database.authenticate_user_secure(payload, "any_password")
                self.assertIsNone(
                    result,
                    f"VULNERABILITY DETECTED: SQLi payload '{payload}' bypassed authentication!"
                )

    def test_valid_authentication_succeeds(self):
        """Verify that legitimate credentials authenticate successfully."""
        user = database.authenticate_user_secure("alice", "alice_secret_pass")
        self.assertIsNotNone(user, "Legitimate credentials failed authentication.")
        self.assertEqual(user["username"], "alice")
        self.assertNotIn("password", user, "Password hash must not be leaked in user model.")

    def test_sql_injection_in_search_returns_literal_match(self):
        """
        Verify that search routine treats SQL metacharacters as literals rather than SQL commands.
        """
        results = database.search_audit_logs_secure("' OR '1'='1")
        # Should not dump entire table, should return 0 results unless literal string exists
        self.assertEqual(len(results), 0, "SQL injection in search should not match arbitrary rows.")

    def test_cryptographic_password_hashing(self):
        """
        Verify password hashing uses PBKDF2-HMAC-SHA256 with unique cryptographic salts.
        """
        password = "ComplexSecurePassword!2026"
        hash1 = security_utils.hash_password(password)
        hash2 = security_utils.hash_password(password)

        self.assertTrue(hash1.startswith("pbkdf2:sha256:600000$"), "Hash must use PBKDF2 with 600,000 iterations.")
        self.assertNotEqual(hash1, hash2, "Identical passwords must produce distinct hashes due to random per-user salts.")

        # Verification tests
        self.assertTrue(security_utils.verify_password(password, hash1), "Valid password must verify.")
        self.assertFalse(security_utils.verify_password("wrong_password", hash1), "Incorrect password must be rejected.")

    def test_rate_limiter_throttles_excessive_attempts(self):
        """
        Verify that the rate limiter throttles repeated requests beyond the allowed threshold.
        """
        test_limiter = security_utils.RateLimiter(max_requests=3, window_seconds=10)
        client_key = "192.168.1.100:test_user"

        # First 3 attempts should be allowed
        self.assertTrue(test_limiter.is_allowed(client_key), "Attempt 1 should succeed.")
        self.assertTrue(test_limiter.is_allowed(client_key), "Attempt 2 should succeed.")
        self.assertTrue(test_limiter.is_allowed(client_key), "Attempt 3 should succeed.")

        # 4th attempt must be blocked
        self.assertFalse(test_limiter.is_allowed(client_key), "Attempt 4 must be throttled by rate limiter.")
        self.assertGreater(test_limiter.retry_after(client_key), 0, "Retry-After must indicate positive wait duration.")

    def test_anti_csrf_token_validation(self):
        """
        Verify anti-CSRF token generation and constant-time validation.
        """
        session_mgr = security_utils.SessionManager()
        user_mock = {"id": 1, "username": "alice"}
        sess_id = session_mgr.create_session(user_mock)

        sess_data = session_mgr.get_session(sess_id)
        valid_csrf = sess_data["csrf_token"]

        # Valid token matches
        self.assertTrue(
            session_mgr.validate_csrf(sess_id, valid_csrf),
            "Valid anti-CSRF token must pass verification."
        )

        # Tampered or forged token must fail
        self.assertFalse(
            session_mgr.validate_csrf(sess_id, "forged_malicious_token_xyz"),
            "Invalid anti-CSRF token must be rejected."
        )

        # Empty token must fail
        self.assertFalse(
            session_mgr.validate_csrf(sess_id, ""),
            "Empty anti-CSRF token must be rejected."
        )

    def test_security_headers_dictionary_completeness(self):
        """
        Verify that all critical defense-in-depth headers are specified.
        """
        required = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Strict-Transport-Security"
        ]
        for h in required:
            self.assertIn(h, security_utils.SECURE_HEADERS, f"Missing critical security header: {h}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
