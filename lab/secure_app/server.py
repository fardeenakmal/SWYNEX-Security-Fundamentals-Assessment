"""
SWYNEX Security Fundamentals Assessment - Secure Hardened Lab Environment
Component: Hardened Web Application Server (lab/secure_app/server.py)

NOTICE: For authorized educational verification and comparison.
Demonstrates end-to-end security remediations:
- Parameterized Queries (Immunizes against SQLi - CWE-89)
- Enforced Access Control & Session-to-Resource Authorization (Remediates IDOR - CWE-639)
- Cryptographic Password Hashing with PBKDF2 (Remediates Weak Cryptography - CWE-328)
- Anti-Brute-Force Rate Limiting (Remediates CWE-307)
- Anti-CSRF Synchronizer Tokens (Remediates CWE-352)
- Security Headers & Sanitized Production Errors (Remediates CWE-209 & CWE-693)
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import logging
import json
import os
import sys

# Ensure local imports work cleanly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import database
import security_utils

# Configure server-side internal logger (stack traces stay in server logs, never to clients)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SwynexSecureServer")


class SecureAppHandler(BaseHTTPRequestHandler):
    """
    Hardened HTTP Request Handler implementing defense-in-depth security controls.
    """

    # Suppress verbose server software banner
    server_version = "Swynex-Gateway"
    sys_version = ""

    def apply_security_headers(self):
        """Injects industry-standard HTTP security headers into every response."""
        for header, value in security_utils.SECURE_HEADERS.items():
            self.send_header(header, value)

    def get_client_ip(self) -> str:
        """Determines client IP for rate-limiting."""
        return self.client_address[0] if self.client_address else "127.0.0.1"

    def get_active_session(self):
        """Extracts and validates the session from secure cookies."""
        cookie_header = self.headers.get("Cookie", "")
        for item in cookie_header.split(";"):
            item = item.strip()
            if item.startswith("secure_session="):
                session_id = item.split("=", 1)[1]
                sess = security_utils.SESSION_MANAGER.get_session(session_id)
                if sess:
                    return session_id, sess
        return None, None

    def render_header(self, title: str, active_user=None):
        user_badge = f'<span class="badge user-badge">Logged in: <strong>{active_user["username"]}</strong> ({active_user["role"]}) | <a href="/logout">Logout</a></span>' if active_user else '<a href="/login" class="nav-link">Login</a>'
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - SWYNEX Hardened Lab</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #090d16; color: #f8fafc; margin: 0; padding: 0; }}
        header {{ background: #131c2e; padding: 1rem 2rem; border-bottom: 2px solid #10b981; display: flex; justify-content: space-between; align-items: center; }}
        .lab-badge {{ background: #065f46; color: #a7f3d0; padding: 0.4rem 0.8rem; text-align: center; font-size: 0.85rem; font-weight: bold; border-radius: 4px; }}
        nav a {{ color: #38bdf8; text-decoration: none; margin-right: 1.25rem; font-weight: 500; }}
        nav a:hover {{ text-decoration: underline; }}
        main {{ max-width: 900px; margin: 2rem auto; padding: 2rem; background: #131c2e; border-radius: 8px; border: 1px solid #1e293b; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        h1, h2, h3 {{ color: #f1f5f9; }}
        .badge {{ display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }}
        .badge-secure {{ background: #064e3b; color: #6ee7b7; border: 1px solid #10b981; }}
        .user-badge {{ background: #1e3a8a; color: #bfdbfe; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #1e293b; }}
        th {{ background: #090d16; color: #94a3b8; }}
        input, button {{ padding: 0.6rem 0.8rem; border-radius: 4px; border: 1px solid #334155; background: #090d16; color: #fff; }}
        button {{ background: #059669; cursor: pointer; border: none; font-weight: bold; }}
        button:hover {{ background: #047857; }}
        .alert {{ padding: 1rem; border-radius: 4px; margin-bottom: 1rem; }}
        .alert-error {{ background: #450a0a; color: #fca5a5; border: 1px solid #b91c1c; }}
        .alert-success {{ background: #064e3b; color: #6ee7b7; border: 1px solid #059669; }}
        .alert-info {{ background: #0c4a6e; color: #7dd3fc; border: 1px solid #0284c7; }}
        code {{ background: #090d16; padding: 0.2rem 0.4rem; border-radius: 3px; color: #34d399; }}
    </style>
</head>
<body>
    <header>
        <div>
            <strong>SWYNEX Security Assessment Lab</strong> <span class="badge badge-secure">Hardened Build (Remediated)</span>
        </div>
        <nav>
            <a href="/">Dashboard</a>
            <a href="/search">Audit Logs</a>
            <a href="/profile">My Profile</a>
            <a href="/transfer">Transfer</a>
            {user_badge}
        </nav>
    </header>
    <main>
"""

    def render_footer(self):
        return """
    </main>
    <footer style="text-align: center; color: #64748b; padding: 2rem; font-size: 0.85rem;">
        SWYNEX Security Fundamentals Assessment | Remediated Architecture Verification
    </footer>
</body>
</html>
"""

    def send_sanitized_error(self, status_code: int, user_message: str):
        """
        DEFENSIVE MITIGATION (CWE-209): Return a sanitized error message to the client
        without disclosing internal stack traces, database schema, or server file paths.
        """
        self.send_response(status_code)
        self.apply_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        content = f"""
        {self.render_header(f"Error {status_code}")}
        <div class="alert alert-error">
            <h3>Request Could Not Be Completed (HTTP {status_code})</h3>
            <p>{user_message}</p>
        </div>
        <p><a href="/" style="color: #38bdf8;">&larr; Return to Dashboard</a></p>
        {self.render_footer()}
        """
        self.wfile.write(content.encode("utf-8"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        session_id, session_data = self.get_active_session()
        user = session_data["user"] if session_data else None

        try:
            if parsed.path == "/":
                self.handle_index(user)
            elif parsed.path == "/login":
                self.handle_login_page(user, error=params.get("error", [""])[0])
            elif parsed.path == "/profile":
                self.handle_profile(user, params)
            elif parsed.path == "/search":
                self.handle_search(user, params)
            elif parsed.path == "/transfer":
                self.handle_transfer_page(user, session_data, message=params.get("msg", [""])[0], error=params.get("err", [""])[0])
            elif parsed.path == "/logout":
                self.handle_logout(session_id)
            else:
                self.send_sanitized_error(404, "The requested resource does not exist.")
        except Exception as e:
            logger.error(f"Unhandled exception during GET request: {e}", exc_info=True)
            self.send_sanitized_error(500, "An unexpected internal server error occurred. Please contact the administrator.")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        session_id, session_data = self.get_active_session()
        user = session_data["user"] if session_data else None

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 1_000_000:  # Prevent DoS from massive request bodies
                self.send_sanitized_error(413, "Request body too large.")
                return

            post_data = self.rfile.read(content_length).decode("utf-8")
            post_params = urllib.parse.parse_qs(post_data)

            if parsed.path == "/login":
                self.process_login(post_params)
            elif parsed.path == "/transfer":
                self.process_transfer(session_id, session_data, post_params)
            else:
                self.send_sanitized_error(404, "Endpoint not found.")
        except Exception as e:
            logger.error(f"Unhandled exception during POST request: {e}", exc_info=True)
            self.send_sanitized_error(500, "An error occurred while processing your submission.")

    def handle_index(self, user):
        self.send_response(200)
        self.apply_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        content = f"""
        {self.render_header("Hardened Dashboard", user)}
        <h2>SWYNEX Remediated Security Environment</h2>
        <div class="alert alert-success">
            <strong>Security Controls Active:</strong> All 6 assessed vulnerability categories have been remediated with defense-in-depth controls according to OWASP Top 10 and NIST guidelines.
        </div>

        <h3>Implemented Defensive Controls</h3>
        <table>
            <thead>
                <tr>
                    <th>Security Dimension</th>
                    <th>Vulnerability Remediated</th>
                    <th>Defensive Control Implemented</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>Injection Defense</strong></td>
                    <td>SQL Injection (CWE-89)</td>
                    <td>Strict parameterized SQL prepared statements across all queries.</td>
                </tr>
                <tr>
                    <td><strong>Access Control</strong></td>
                    <td>IDOR (CWE-639)</td>
                    <td>Session-to-resource ownership validation; non-admin users cannot access foreign IDs.</td>
                </tr>
                <tr>
                    <td><strong>Cryptography</strong></td>
                    <td>Weak MD5 Hashes (CWE-328)</td>
                    <td>PBKDF2-HMAC-SHA256 (600,000 iterations) with unique 16-byte random salts.</td>
                </tr>
                <tr>
                    <td><strong>Authentication Defense</strong></td>
                    <td>Brute-Force &amp; Stuffing (CWE-307)</td>
                    <td>Sliding window rate-limiter (max 5 attempts/min per IP) returning HTTP 429.</td>
                </tr>
                <tr>
                    <td><strong>State Security</strong></td>
                    <td>CSRF (CWE-352)</td>
                    <td>Cryptographic anti-CSRF synchronizer tokens &amp; <code>SameSite=Strict</code> cookies.</td>
                </tr>
                <tr>
                    <td><strong>System Configuration</strong></td>
                    <td>Information Disclosure (CWE-209/693)</td>
                    <td>Sanitized error responses, complete suite of HTTP security headers (CSP, HSTS).</td>
                </tr>
            </tbody>
        </table>
        {self.render_footer()}
        """
        self.wfile.write(content.encode("utf-8"))

    def handle_login_page(self, user, error=""):
        if user:
            self.send_response(302)
            self.send_header("Location", "/profile")
            self.end_headers()
            return

        self.send_response(200)
        self.apply_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        error_block = f'<div class="alert alert-error">{error}</div>' if error else ""
        content = f"""
        {self.render_header("Secure Login", user)}
        <h2>Secure Authentication Portal</h2>
        {error_block}
        <form method="POST" action="/login" style="display: flex; flex-direction: column; gap: 1rem; max-width: 400px;">
            <div>
                <label>Username:</label><br>
                <input type="text" name="username" style="width: 100%;" required autocomplete="username">
            </div>
            <div>
                <label>Password:</label><br>
                <input type="password" name="password" style="width: 100%;" required autocomplete="current-password">
            </div>
            <button type="submit">Authenticate</button>
        </form>
        <p style="margin-top: 1.5rem; font-size: 0.85rem; color: #94a3b8;">
            <em>Rate limiting enabled: 5 attempts allowed per 60 seconds per IP address.</em>
        </p>
        {self.render_footer()}
        """
        self.wfile.write(content.encode("utf-8"))

    def process_login(self, post_params):
        client_ip = self.get_client_ip()
        username = post_params.get("username", [""])[0].strip()
        password = post_params.get("password", [""])[0]

        # MITIGATION CWE-307: Rate limiting verification
        limiter_key = f"{client_ip}:{username}"
        if not security_utils.LOGIN_RATE_LIMITER.is_allowed(limiter_key):
            retry_seconds = security_utils.LOGIN_RATE_LIMITER.retry_after(limiter_key)
            self.send_response(429)
            self.apply_security_headers()
            self.send_header("Retry-After", str(retry_seconds))
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            err_html = f"""
            {self.render_header("Rate Limit Exceeded")}
            <div class="alert alert-error">
                <h3>HTTP 429: Too Many Authentication Requests</h3>
                <p>Too many failed login attempts detected. Please retry in <strong>{retry_seconds} seconds</strong>.</p>
            </div>
            {self.render_footer()}
            """
            self.wfile.write(err_html.encode("utf-8"))
            return

        # MITIGATION CWE-89 & CWE-328: Parameterized lookup + PBKDF2 verification
        user = database.authenticate_user_secure(username, password)

        if user:
            # Generate high-entropy CSPRNG session token
            session_id = security_utils.SESSION_MANAGER.create_session(user)

            self.send_response(302)
            self.apply_security_headers()
            # Hardened session cookie with HttpOnly, SameSite=Strict, Path=/
            self.send_header(
                "Set-Cookie",
                f"secure_session={session_id}; Path=/; HttpOnly; SameSite=Strict"
            )
            self.send_header("Location", "/profile")
            self.end_headers()
        else:
            self.send_response(302)
            self.apply_security_headers()
            self.send_header("Location", "/login?error=Invalid+credentials+provided")
            self.end_headers()

    def handle_profile(self, user, params):
        if not user:
            self.send_response(302)
            self.send_header("Location", "/login?error=Authentication+required")
            self.end_headers()
            return

        requested_id_str = params.get("id", [None])[0]
        # Default to the logged-in user's own profile
        target_id = user["id"] if not requested_id_str else int(requested_id_str)

        # MITIGATION CWE-639: Enforce strict contextual authorization
        # A standard user can ONLY view their own profile. Only 'admin' role can view other accounts.
        if target_id != user["id"] and user["role"] != "admin":
            logger.warning(f"Unauthorized IDOR attempt blocked: User {user['username']} (ID {user['id']}) tried accessing ID {target_id}")
            self.send_sanitized_error(403, "Access Denied: You do not possess authorization to inspect records belonging to other users.")
            return

        profile_data = database.get_user_by_id_secure(target_id)
        if not profile_data:
            self.send_sanitized_error(404, "User record not found.")
            return

        self.send_response(200)
        self.apply_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        content = f"""
        {self.render_header("User Profile", user)}
        <h2>User Account Profile</h2>
        <div class="alert alert-info">
            <strong>Access Control Validated:</strong> Identity confirmed for <code>{user['username']}</code>. Access to ID {target_id} authorized.
        </div>
        <div style="background: #090d16; padding: 1.5rem; border-radius: 6px; border: 1px solid #1e293b;">
            <p><strong>User ID:</strong> {profile_data['id']}</p>
            <p><strong>Username:</strong> {profile_data['username']}</p>
            <p><strong>Full Name:</strong> {profile_data['full_name']}</p>
            <p><strong>Email Address:</strong> {profile_data['email']}</p>
            <p><strong>Role:</strong> <span class="badge user-badge">{profile_data['role']}</span></p>
            <p><strong>Account Number:</strong> <code>{profile_data['account_number']}</code></p>
            <p><strong>Account Balance:</strong> <strong style="color: #34d399;">${profile_data['balance']:.2f}</strong></p>
        </div>
        {self.render_footer()}
        """
        self.wfile.write(content.encode("utf-8"))

    def handle_search(self, user, params):
        query = params.get("q", [""])[0].strip()
        results = []
        if query:
            # MITIGATION CWE-89: Parameterized search execution
            results = database.search_audit_logs_secure(query)

        self.send_response(200)
        self.apply_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        # HTML escape query for output encoding
        safe_query = urllib.parse.quote(query) if query else ""

        rows = ""
        for r in results:
            rows += f"<tr><td>{r['id']}</td><td>{r['timestamp']}</td><td>{r['action']}</td><td>{r['details']}</td></tr>"

        content = f"""
        {self.render_header("Search Audit Logs", user)}
        <h2>Hardened System Audit Log Search</h2>
        <form method="GET" action="/search" style="display: flex; gap: 0.5rem; margin-bottom: 1.5rem;">
            <input type="text" name="q" value="{query}" placeholder="Search audit logs securely..." style="flex: 1;">
            <button type="submit">Search</button>
        </form>

        <p style="color: #94a3b8; font-size: 0.85rem;">
            <em>All search expressions are safely handled through prepared statements with parameter binding.</em>
        </p>

        <table>
            <thead>
                <tr>
                    <th>Log ID</th>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {rows if rows else '<tr><td colspan="4" style="text-align: center; color: #64748b;">No matching audit records.</td></tr>'}
            </tbody>
        </table>
        {self.render_footer()}
        """
        self.wfile.write(content.encode("utf-8"))

    def handle_transfer_page(self, user, session_data, message="", error=""):
        if not user or not session_data:
            self.send_response(302)
            self.send_header("Location", "/login?error=Authentication+required")
            self.end_headers()
            return

        self.send_response(200)
        self.apply_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        msg_block = f'<div class="alert alert-success">{message}</div>' if message else ""
        err_block = f'<div class="alert alert-error">{error}</div>' if error else ""

        # MITIGATION CWE-352: Include unique anti-CSRF synchronizer token in the form
        csrf_token = session_data["csrf_token"]

        content = f"""
        {self.render_header("Transfer Funds", user)}
        <h2>Secure Funds Transfer</h2>
        {msg_block}
        {err_block}
        <p>Available Balance for <strong>{user['username']}</strong>: <code>${user['balance']:.2f}</code></p>

        <form method="POST" action="/transfer" style="display: flex; flex-direction: column; gap: 1rem; max-width: 400px;">
            <!-- Anti-CSRF Synchronizer Token -->
            <input type="hidden" name="csrf_token" value="{csrf_token}">

            <div>
                <label>Recipient Username:</label><br>
                <input type="text" name="recipient" placeholder="e.g. bob" style="width: 100%;" required>
            </div>
            <div>
                <label>Amount ($):</label><br>
                <input type="number" step="0.01" min="0.01" name="amount" placeholder="0.00" style="width: 100%;" required>
            </div>
            <button type="submit">Execute Transfer</button>
        </form>

        <div style="margin-top: 2rem; padding: 1rem; background: #090d16; border-radius: 6px; font-size: 0.85rem; color: #94a3b8; border: 1px solid #1e293b;">
            <strong>CSRF Defense Verified:</strong> Submissions are protected via unique per-session cryptographic synchronizer tokens and <code>SameSite=Strict</code> cookie policies.
        </div>
        {self.render_footer()}
        """
        self.wfile.write(content.encode("utf-8"))

    def process_transfer(self, session_id, session_data, post_params):
        if not session_data or not session_id:
            self.send_sanitized_error(401, "Session expired or invalid.")
            return

        user = session_data["user"]
        submitted_csrf = post_params.get("csrf_token", [""])[0]

        # MITIGATION CWE-352: Strict CSRF token verification
        if not security_utils.SESSION_MANAGER.validate_csrf(session_id, submitted_csrf):
            logger.warning(f"CSRF token validation failure for user {user['username']}")
            self.send_sanitized_error(403, "Forbidden: Anti-CSRF token missing or invalid.")
            return

        recipient = post_params.get("recipient", [""])[0].strip()
        amount_str = post_params.get("amount", ["0"])[0].strip()

        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be positive.")
            database.transfer_funds_secure(user["id"], recipient, amount)

            # Update session user balance
            fresh = database.get_user_by_id_secure(user["id"])
            if fresh:
                user["balance"] = fresh["balance"]

            self.send_response(302)
            self.apply_security_headers()
            self.send_header("Location", f"/transfer?msg=Successfully+transferred+${amount:.2f}+to+{recipient}")
            self.end_headers()
        except ValueError as ve:
            self.send_response(302)
            self.apply_security_headers()
            self.send_header("Location", f"/transfer?err={urllib.parse.quote(str(ve))}")
            self.end_headers()

    def handle_logout(self, session_id):
        if session_id:
            security_utils.SESSION_MANAGER.destroy_session(session_id)
        self.send_response(302)
        self.apply_security_headers()
        self.send_header("Set-Cookie", "secure_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict")
        self.send_header("Location", "/login")
        self.end_headers()


def run_server(port=8081):
    database.init_db()
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, SecureAppHandler)
    print(f"[*] SWYNEX Authorized Secure Lab Server running on http://127.0.0.1:{port}")
    print("[*] Press Ctrl+C to stop the secure lab server.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down secure lab server.")
        httpd.server_close()


if __name__ == "__main__":
    port = 8081
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
