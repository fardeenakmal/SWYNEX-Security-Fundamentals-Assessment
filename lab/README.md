# SWYNEX Security Fundamentals Assessment - Lab Environments

This directory contains the authorized, self-contained educational testbeds created for the **SWYNEX Security Fundamentals Assessment**.

## Lab Architecture Overview

The lab contains two independent, zero-dependency Python applications:

1. **`vulnerable_app/` (Port 8080)**:
   - An intentionally insecure web application designed to demonstrate fundamental security vulnerabilities under controlled conditions.
   - Contains:
     - **SQL Injection (CWE-89)** in authentication (`/login`) and log searching (`/search`).
     - **Insecure Direct Object Reference (IDOR - CWE-639)** in profile lookup (`/profile?id=X`).
     - **Cryptographic Failure (CWE-328 / CWE-312)** using legacy unsalted MD5 password hashes.
     - **Missing Rate Limiting & Account Lockout (CWE-307)** allowing automated brute-force attacks.
     - **Security Misconfiguration (CWE-209 / CWE-693)** exposing debug stack traces and omitting HTTP security headers.
     - **Cross-Site Request Forgery (CSRF - CWE-352)** on state-changing balance transfers.

2. **`secure_app/` (Port 8081)**:
   - The remediated, hardened production-grade implementation addressing all identified risks.
   - Implements:
     - Parameterized SQL prepared statements.
     - Role-based and session-to-resource ownership authorization.
     - PBKDF2-HMAC-SHA256 password hashing with 600,000 iterations and CSPRNG salt.
     - Sliding-window rate limiter (5 requests/minute per IP) returning `HTTP 429`.
     - Cryptographic anti-CSRF synchronizer tokens and `SameSite=Strict` cookies.
     - Complete suite of defensive HTTP security headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `HSTS`, `Permissions-Policy`).
     - Generic, sanitized user-facing error pages with internal logging.

---

## Quickstart Instructions

### 1. Running the Vulnerable Lab Server (Port 8080)
```bash
python3 lab/vulnerable_app/server.py
```
Open your browser to: [http://127.0.0.1:8080](http://127.0.0.1:8080)

### 2. Running the Hardened Secure Server (Port 8081)
```bash
python3 lab/secure_app/server.py
```
Open your browser to: [http://127.0.0.1:8081](http://127.0.0.1:8081)

---

## Seed Accounts (Authorized Testing)

| Username | Plaintext Password | Role | Account ID | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `admin` | `AdminMaster!2026` | Administrator | 1 | Privileged administrative access |
| `alice` | `alice_secret_pass` | Standard User | 2 | Primary victim account ($1250.50) |
| `bob` | `bob_password_123` | Standard User | 3 | Secondary user account ($420.00) |
| `charlie` | `qwerty2026` | Standard User | 4 | Low-balance user account ($85.25) |

---

## Legal & Ethical Disclaimer
This lab software is provided solely for educational and training purposes in authorized environments. Never perform security testing against systems or networks without explicit, documented authorization from the system owner.
