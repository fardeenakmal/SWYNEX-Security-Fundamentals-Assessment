"""
SWYNEX Security Fundamentals Assessment - Authorized Vulnerable Lab Environment
Component: Vulnerable Web Application Server (lab/vulnerable_app/server.py)

NOTICE: For authorized educational lab training only.
Demonstrates common security vulnerabilities in a controlled localhost environment.
Do NOT deploy to production or expose to public untrusted networks.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import traceback
import json
import os
import sys

# Ensure local imports work cleanly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import database

# In-memory session store (simple session ID -> user dict)
SESSIONS = {}


class VulnerableAppHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler intentionally exhibiting critical security flaws:
    - Missing Security Headers (CWE-693)
    - Detailed Debug Error Stacks (CWE-209)
    - SQL Injection endpoints (CWE-89)
    - Insecure Direct Object References (CWE-639)
    - Missing CSRF Validation (CWE-352)
    - Missing Rate Limiting (CWE-307)
    """

    server_version = "Swynex-Lab-Core/1.0.0-DEBUG"  # Information disclosure in Server header

    def get_session(self):
        """Extracts session cookie without security validation."""
        cookie_header = self.headers.get("Cookie", "")
        for item in cookie_header.split(";"):
            item = item.strip()
            if item.startswith("session_id="):
                session_id = item.split("=", 1)[1]
                return SESSIONS.get(session_id)
        return None

    def render_header(self, title: str, active_user=None):
        user_badge = f'<span class="badge user-badge">Logged in: <strong>{active_user["username"]}</strong> ({active_user["role"]}) | <a href="/logout">Logout</a></span>' if active_user else '<a href="/login" class="nav-link">Login</a>'
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{title} - SWYNEX Vulnerable Lab</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 0; }}
        header {{ background: #1e293b; padding: 1rem 2rem; border-bottom: 2px solid #ef4444; display: flex; justify-content: space-between; align-items: center; }}
        .lab-warning {{ background: #dc2626; color: white; padding: 0.5rem 1rem; text-align: center; font-size: 0.85rem; font-weight: bold; letter-spacing: 0.05em; }}
        nav a {{ color: #38bdf8; text-decoration: none; margin-right: 1.25rem; font-weight: 500; }}
        nav a:hover {{ text-decoration: underline; }}
        main {{ max-width: 900px; margin: 2rem auto; padding: 2rem; background: #1e293b; border-radius: 8px; border: 1px solid #334155; }}
        h1, h2, h3 {{ color: #f1f5f9; }}
        .badge {{ display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }}
        .badge-vuln {{ background: #7f1d1d; color: #fecaca; border: 1px solid #dc2626; }}
        .user-badge {{ background: #1e3a8a; color: #bfdbfe; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; }}
        input, button {{ padding: 0.6rem 0.8rem; border-radius: 4px; border: 1px solid #475569; background: #0f172a; color: #fff; }}
        button {{ background: #2563eb; cursor: pointer; border: none; font-weight: bold; }}
        button:hover {{ background: #1d4ed8; }}
        .alert {{ padding: 1rem; border-radius: 4px; margin-bottom: 1rem; }}
        .alert-error {{ background: #450a0a; color: #fca5a5; border: 1px solid #b91c1c; }}
        .alert-success {{ background: #064e3b; color: #6ee7b7; border: 1px solid #059669; }}
        code {{ background: #0f172a; padding: 0.2rem 0.4rem; border-radius: 3px; color: #f43f5e; }}
        pre {{ background: #020617; padding: 1rem; border-radius: 6px; overflow-x: auto; color: #ef4444; border: 1px solid #b91c1c; }}
    </style>
</head>
<body>
    <div class="lab-warning">
        AUTHORIZED LAB TESTBED ONLY - INSECURE CODE PATHS ACTIVE FOR EDUCATIONAL AUDITING
    </div>
    <header>
        <div>
            <strong>SWYNEX Security Assessment Lab</strong> <span class="badge badge-vuln">Vulnerable Build</span>
        </div>
        <nav>
            <a href="/">Dashboard</a>
            <a href="/search">Audit Logs (SQLi)</a>
            <a href="/profile">My Profile (IDOR)</a>
            <a href="/transfer">Transfer (CSRF)</a>
            {user_badge}
        </nav>
    </header>
    <main>
"""

    def render_footer(self):
        return """
    </main>
    <footer style="text-align: center; color: #64748b; padding: 2rem; font-size: 0.85rem;">
        SWYNEX Security Fundamentals Assessment | Educational Reference Lab
    </footer>
</body>
</html>
"""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        user = self.get_session()

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
                self.handle_transfer_page(user, message=params.get("msg", [""])[0])
            elif parsed.path == "/logout":
                self.handle_logout()
            else:
                self.send_error(404, "Page Not Found")
        except Exception as e:
            # VULNERABILITY CWE-209: Information Exposure Through an Error Message
            # Returning full traceback directly in the HTTP response
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            err_html = f"""
            {self.render_header("500 Server Error - Debug Trace")}
            <div class="alert alert-error">
                <h3>Internal Server Error (Debug Mode Active)</h3>
                <p>The server encountered an unhandled exception while processing your request.</p>
                <p><strong>Exception:</strong> <code>{str(e)}</code></p>
                <h4>Full Stack Trace:</h4>
                <pre>{traceback.format_exc()}</pre>
            </div>
            {self.render_footer()}
            """
            self.wfile.write(err_html.encode("utf-8"))

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        user = self.get_session()

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")
            post_params = urllib.parse.parse_qs(post_data)

            if parsed.path == "/login":
                self.process_login(post_params)
            elif parsed.path == "/transfer":
                self.process_transfer(user, post_params)
            else:
                self.send_error(404, "Endpoint Not Found")
        except Exception as e:
            # VULNERABILITY: Verbose error output on POST failures
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            err_html = f"""
            {self.render_header("500 POST Error")}
            <div class="alert alert-error">
                <h3>POST Handler Exception</h3>
                <pre>{traceback.format_exc()}</pre>
            </div>
            {self.render_footer()}
            """
            self.wfile.write(err_html.encode("utf-8"))

    def handle_index(self, user):
        self.send_response(200)
        # Note: Missing security headers like Content-Security-Policy, X-Frame-Options, X-Content-Type-Options
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        content = f"""
        {self.render_header("Lab Overview", user)}
        <h2>SWYNEX Security Fundamentals Training Environment</h2>
        <p>This lab environment has been constructed to simulate real-world web application components containing fundamental security design and implementation flaws.</p>
        
        <h3>Assessment Scope & Demonstration Endpoints</h3>
        <table>
            <thead>
                <tr>
                    <th>Component / Endpoint</th>
                    <th>Vulnerability Class</th>
                    <th>OWASP Top 10</th>
                    <th>CVSS Base</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><code>/login</code> (Form Handler)</td>
                    <td>SQL Injection (SQLi) via dynamic string concatenation</td>
                    <td>A03:2021 - Injection</td>
                    <td>9.8 (Critical)</td>
                </tr>
                <tr>
                    <td><code>/profile?id=&lt;id&gt;</code></td>
                    <td>Insecure Direct Object Reference (IDOR)</td>
                    <td>A01:2021 - Broken Access Control</td>
                    <td>7.5 (High)</td>
                </tr>
                <tr>
                    <td><code>Database Auth Layer</code></td>
                    <td>Cryptographic Failure (Unsalted MD5 Password Hashes)</td>
                    <td>A02:2021 - Cryptographic Failures</td>
                    <td>7.4 (High)</td>
                </tr>
                <tr>
                    <td><code>/login</code> (Authentication API)</td>
                    <td>Missing Rate Limiting &amp; Credential Stuffing Risk</td>
                    <td>A07:2021 - Identification &amp; Auth Failures</td>
                    <td>5.3 (Medium)</td>
                </tr>
                <tr>
                    <td><code>Global HTTP Responses</code></td>
                    <td>Missing Security Headers &amp; Verbose Debug Stack Traces</td>
                    <td>A05:2021 - Security Misconfiguration</td>
                    <td>5.3 (Medium)</td>
                </tr>
                <tr>
                    <td><code>/transfer</code> (State-changing POST)</td>
                    <td>Missing Cross-Site Request Forgery (CSRF) Tokens</td>
                    <td>A04:2021 - Insecure Design</td>
                    <td>6.5 (Medium)</td>
                </tr>
            </tbody>
        </table>

        <div style="margin-top: 2rem; padding: 1rem; background: #0f172a; border-radius: 6px; border-left: 4px solid #38bdf8;">
            <strong>Test Accounts in Seed Database:</strong>
            <ul>
                <li><code>admin</code> / <code>AdminMaster!2026</code> (Administrator)</li>
                <li><code>alice</code> / <code>alice_secret_pass</code> (User ID 2, Balance: $1250.50)</li>
                <li><code>bob</code> / <code>bob_password_123</code> (User ID 3, Balance: $420.00)</li>
                <li><code>charlie</code> / <code>qwerty2026</code> (User ID 4, Balance: $85.25)</li>
            </ul>
        </div>
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
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        error_block = f'<div class="alert alert-error">{error}</div>' if error else ""
        content = f"""
        {self.render_header("Login", user)}
        <h2>Authentication Portal</h2>
        {error_block}
        <form method="POST" action="/login" style="display: flex; flex-direction: column; gap: 1rem; max-width: 400px;">
            <div>
                <label>Username:</label><br>
                <input type="text" name="username" style="width: 100%;" required>
            </div>
            <div>
                <label>Password:</label><br>
                <input type="password" name="password" style="width: 100%;" required>
            </div>
            <button type="submit">Log In</button>
        </form>
        <p style="margin-top: 1.5rem; font-size: 0.85rem; color: #94a3b8;">
            <em>Note: This endpoint has no request throttling or rate limiting. An attacker could automate thousands of attempts per minute without interruption.</em>
        </p>
        {self.render_footer()}
        """
        self.wfile.write(content.encode("utf-8"))

    def process_login(self, post_params):
        username = post_params.get("username", [""])[0]
        password = post_params.get("password", [""])[0]

        # VULNERABLE: Direct call to query concatenating user input
        user = database.authenticate_user_vulnerable(username, password)

        if user:
            # Insecure session creation: simple sequential or predictable ID, missing HttpOnly/SameSite/Secure attributes
            session_id = f"sess_{user['id']}_{user['username']}"
            SESSIONS[session_id] = user

            self.send_response(302)
            # VULNERABILITY: Missing HttpOnly, SameSite, Secure flags
            self.send_header("Set-Cookie", f"session_id={session_id}; Path=/")
            self.send_header("Location", f"/profile?id={user['id']}")
            self.end_headers()
        else:
            self.send_response(302)
            self.send_header("Location", "/login?error=Invalid+credentials")
            self.end_headers()

    def handle_profile(self, user, params):
        # VULNERABILITY CWE-639: Insecure Direct Object Reference (IDOR)
        # The user ID is read directly from the query parameter without verifying
        # that the authenticated session actually owns this profile record!
        requested_id = params.get("id", [None])[0]
        if not requested_id:
            if user:
                requested_id = user["id"]
            else:
                self.send_response(302)
                self.send_header("Location", "/login?error=Please+log+in")
                self.end_headers()
                return

        profile_data = database.get_user_by_id_vulnerable(int(requested_id))

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        if profile_data:
            idor_warning = ""
            if user and str(user["id"]) != str(requested_id):
                idor_warning = f"""
                <div class="alert alert-error">
                    <strong>Vulnerability Triggered (IDOR):</strong> You are authenticated as <code>{user['username']}</code> (ID: {user['id']}), but viewing private record of <code>{profile_data['username']}</code> (ID: {profile_data['id']})!
                </div>
                """

            content = f"""
            {self.render_header("User Profile", user)}
            <h2>User Account Profile</h2>
            {idor_warning}
            <div style="background: #0f172a; padding: 1.5rem; border-radius: 6px;">
                <p><strong>User ID:</strong> {profile_data['id']}</p>
                <p><strong>Username:</strong> {profile_data['username']}</p>
                <p><strong>Full Name:</strong> {profile_data['full_name']}</p>
                <p><strong>Email Address:</strong> {profile_data['email']}</p>
                <p><strong>Role:</strong> <span class="badge user-badge">{profile_data['role']}</span></p>
                <p><strong>Account Number:</strong> <code>{profile_data['account_number']}</code></p>
                <p><strong>Account Balance:</strong> <strong style="color: #4ade80;">${profile_data['balance']:.2f}</strong></p>
            </div>
            <p style="margin-top: 1rem; color: #94a3b8; font-size: 0.9rem;">
                Try changing the <code>?id=1</code>, <code>?id=2</code>, <code>?id=3</code> URL parameter to view other users' sensitive private financial records without authorization.
            </p>
            {self.render_footer()}
            """
        else:
            content = f"""
            {self.render_header("Profile Not Found", user)}
            <div class="alert alert-error">User profile ID {requested_id} does not exist.</div>
            {self.render_footer()}
            """
        self.wfile.write(content.encode("utf-8"))

    def handle_search(self, user, params):
        query = params.get("q", [""])[0]
        results = []
        if query:
            # VULNERABILITY: SQL injection in search term
            results = database.search_audit_logs_vulnerable(query)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        rows = ""
        for r in results:
            rows += f"<tr><td>{r['id']}</td><td>{r['timestamp']}</td><td>{r['action']}</td><td>{r['details']}</td></tr>"

        content = f"""
        {self.render_header("System Audit Logs Search", user)}
        <h2>System Audit Log Search</h2>
        <form method="GET" action="/search" style="display: flex; gap: 0.5rem; margin-bottom: 1.5rem;">
            <input type="text" name="q" value="{query}" placeholder="Search audit logs..." style="flex: 1;">
            <button type="submit">Search</button>
        </form>

        <p style="color: #94a3b8; font-size: 0.85rem;">
            <em>Demonstration: This search input is vulnerable to SQL Injection due to lack of query parameterization.</em>
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
                {rows if rows else '<tr><td colspan="4" style="text-align: center; color: #64748b;">No records matched your search query.</td></tr>'}
            </tbody>
        </table>
        {self.render_footer()}
        """
        self.wfile.write(content.encode("utf-8"))

    def handle_transfer_page(self, user, message=""):
        if not user:
            self.send_response(302)
            self.send_header("Location", "/login?error=Please+log+in+first")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        msg_block = f'<div class="alert alert-success">{message}</div>' if message else ""

        content = f"""
        {self.render_header("Transfer Funds", user)}
        <h2>Internal Funds Transfer</h2>
        {msg_block}
        <p>Available Balance for <strong>{user['username']}</strong>: <code>${user['balance']:.2f}</code></p>
        
        <!-- VULNERABILITY CWE-352: Form lacks anti-CSRF token -->
        <form method="POST" action="/transfer" style="display: flex; flex-direction: column; gap: 1rem; max-width: 400px;">
            <div>
                <label>Recipient Username:</label><br>
                <input type="text" name="recipient" placeholder="e.g. bob" style="width: 100%;" required>
            </div>
            <div>
                <label>Amount ($):</label><br>
                <input type="number" step="0.01" name="amount" placeholder="0.00" style="width: 100%;" required>
            </div>
            <button type="submit">Transfer Funds</button>
        </form>

        <div style="margin-top: 2rem; padding: 1rem; background: #0f172a; border-radius: 6px; font-size: 0.85rem; color: #94a3b8;">
            <strong>CSRF Risk Explanation:</strong> Because this state-changing endpoint has no synchronizer token and relies on standard ambient cookies without <code>SameSite</code> restrictions, an external malicious website could trick a victim's browser into submitting this form in the background.
        </div>
        {self.render_footer()}
        """
        self.wfile.write(content.encode("utf-8"))

    def process_transfer(self, user, post_params):
        if not user:
            self.send_response(302)
            self.send_header("Location", "/login?error=Unauthorized")
            self.end_headers()
            return

        recipient = post_params.get("recipient", [""])[0]
        amount_str = post_params.get("amount", ["0"])[0]
        try:
            amount = float(amount_str)
        except ValueError:
            amount = 0.0

        # Note: No CSRF token validation performed!
        database.transfer_funds_vulnerable(user["id"], recipient, amount)

        # Refresh in-memory user balance
        updated = database.get_user_by_id_vulnerable(user["id"])
        if updated:
            user["balance"] = updated["balance"]

        self.send_response(302)
        self.send_header("Location", f"/transfer?msg=Successfully+transferred+${amount:.2f}+to+{recipient}")
        self.end_headers()

    def handle_logout(self):
        self.send_response(302)
        self.send_header("Set-Cookie", "session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
        self.send_header("Location", "/login")
        self.end_headers()


def run_server(port=8080):
    database.init_db()
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, VulnerableAppHandler)
    print(f"[*] SWYNEX Authorized Vulnerable Lab Server running on http://127.0.0.1:{port}")
    print("[*] Press Ctrl+C to stop the training lab.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down vulnerable lab server.")
        httpd.server_close()


if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
